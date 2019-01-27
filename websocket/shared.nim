import asyncdispatch, asyncnet, streams, nativesockets, strutils, tables,
  times, oids, random, options, endians

type
  ProtocolError* = object of Exception

  Opcode* {.pure.} = enum
    Cont = 0x0 ## Continued Frame (when the previous was fin = 0)
    Text = 0x1 ## Text frames need to be valid UTF-8
    Binary = 0x2 ## Binary frames can be anything.
    Close = 0x8 ## Socket is being closed by the remote, or we intend to close it.
    Ping = 0x9 ## Ping
    Pong = 0xa ## Pong. Needs to echo back the app data in ping.

  Frame* = tuple
    ## A frame read off the netlayer.

    fin: bool ## Last frame in current packet.
    rsv1: bool ## Extension data: negotiated in http prequel, or 0.
    rsv2: bool ## Extension data: negotiated in http prequel, or 0.
    rsv3: bool ## Extension data: negotiated in http prequel, or 0.

    masked: bool ## If the frame was received masked/is supposed to be masked.
    
    maskingKey: string ## The masking key if the frame is supposed to be masked.
                       ## If masked is false, this is an empty string.
                       ## Otherwise, length is 4.

    opcode: Opcode ## The opcode of this frame.

    data: string ## App data
  
  SocketKind* {.pure.} = enum
    Client, Server
  
  AsyncWebSocketObj = object of RootObj
    sock*: AsyncSocket
    protocol*: string
    kind*: SocketKind

  AsyncWebSocket* = ref AsyncWebSocketObj

const
  MaxHeaderSize = 14

const
  bit0 = 0x80

  len7  = int64(125)
  len16 = int64(not (uint16(0)))
  len64 = int64(not (uint64(0)) shr 1)

proc htonll(x: uint64): uint64 =
  ## Converts 64-bit unsigned integers from host to network byte order.
  ## On machines where the host byte order is the same as network byte order,
  ## this is a no-op; otherwise, it performs a 8-byte swap operation.
  when cpuEndian == bigEndian: result = x
  else: result = (x shr 56'u64) or
                 (x shr 40'u64 and 0xff00'u64) or
                 (x shr 24'u64 and 0xff0000'u64) or
                 (x shr 8'u64 and 0xff000000'u64) or
                 (x shl 8'u64 and 0xff00000000'u64) or
                 (x shr 24'u64 and 0xff0000000000'u64) or
                 (x shl 40'u64 and 0xff000000000000'u64) or
                 (x shl 56'u64)

proc mask*(data: var string, maskingKey: string) =
  for i in 0..data.high:
    data[i] = (data[i].uint8 xor maskingKey[i mod 4].uint8).char

template unmask*(data: var string, maskingKey: string): auto =
  mask(data, maskingKey)

proc generateMaskingKey*: string =
  when not defined(websocketUnmaskedByDefault):
    template rnd: untyped =
      when declared(random.rand):
        rand(255).char
      else:
        random(256).char

    result = newString(4)
    result[0] = rnd
    result[1] = rnd
    result[2] = rnd
    result[3] = rnd
  else:
    result = ""

proc makeFrame*(f: Frame): string =
  ## Generate valid websocket frame data, ready to be sent over the wire.
  ## This is useful for rolling your own impl, for example
  ## with AsyncHttpServer

  # Based on https://github.com/gobwas/ws/blob/6499edb2f13/write.go#L51
  var header: array[MaxHeaderSize, byte]
  if f.fin:
    header[0] = header[0] or bit0

  if f.rsv1: header[0] = header[0] or (1 shl 6)
  if f.rsv2: header[0] = header[0] or (1 shl 5)
  if f.rsv3: header[0] = header[0] or (1 shl 4)

  header[0] = header[0] or f.opcode.byte

  var headerLen = 2
  let size = f.data.len
  if size <= len7:
    header[1] = byte(size)
    headerLen = 2
  elif size <= len16:
    header[1] = 126
    let value = uint16(size)
    bigEndian16(addr header[2], unsafeAddr value)
    headerLen = 4
  elif size <= len64:
    header[1] = 127
    let value = uint64(size)
    bigEndian64(addr header[2], unsafeAddr value)
    headerLen = 10
  else:
    raise newException(ProtocolError, "Cannot handle such a long message.")

  var data = f.data
  if f.masked:
    assert f.maskingKey.len == 4
    header[1] = header[1] or bit0
    mask(data, f.maskingKey)
    copyMem(addr header[headerLen], unsafeAddr f.maskingKey[0], 4)
    headerLen += 4

  result = newString(headerLen + data.len)
  copyMem(addr result[0], addr header[0], headerLen)
  copyMem(addr result[headerLen], addr data[0], data.len)

proc makeFrame*(opcode: Opcode, data: string, maskingKey = generateMaskingKey()): string =
  ## A convenience shorthand.
  result = makeFrame((fin: true, rsv1: false, rsv2: false, rsv3: false,
    masked: maskingKey.len != 0, maskingKey: maskingKey,
    opcode: opcode, data: data))

proc makeFrame*(opcode: Opcode, data: string, masked: bool): string {.deprecated.} =
  ## A convenience shorthand.
  ## **Deprecated since 0.3.2**: Frames should always be masked, either
  ## call makeFrame(opcode, data) or call makeFrame(opcode, data, maskingKey).
  result = makeFrame(opcode, data, if masked: generateMaskingKey() else: "")

proc recvFrame*(ws: AsyncSocket): Future[Frame] {.async.} =
  ## Read a full frame off the given socket.
  ##
  ## You probably want to use the higher-level variant, `readData`.

  const lookupTable = [128u8, 64, 32, 16, 8, 4, 2, 1]

  template `[]`(b: byte, idx: int): bool =
    (b and lookupTable[idx]) != 0

  var f: Frame
  let hdr = await ws.recv(2)
  if hdr.len != 2: raise newException(IOError, "socket closed")

  let b0 = hdr[0].uint8
  let b1 = hdr[1].uint8

  f.fin  = b0[0]
  f.rsv1 = b0[1]
  f.rsv2 = b0[2]
  f.rsv3 = b0[3]
  let opc = b0 and 0x0f
  try:
    f.opcode = opc.Opcode
  except RangeError:
    ws.close()
    raise newException(ProtocolError, "received invalid opcode: " & repr(opc))

  if f.rsv1 or f.rsv2 or f.rsv3:
    raise newException(ProtocolError,
      "websocket tried to use non-negotiated extension")

  let hdrLen = int(b1 and 0x7f)
  let finalLen = case hdrLen:
    of 0x7e:
      var lenstr = await ws.recv(2, {})
      if lenstr.len != 2: raise newException(IOError, "socket closed")

      cast[ptr uint16](lenstr[0].addr)[].htons.int
    of 0x7f:
      var lenstr = await ws.recv(8, {})
      if lenstr.len != 8: raise newException(IOError, "socket closed")

      let realLen = cast[ptr uint64](lenstr[0].addr)[].htonll
      if realLen > high(int).uint64:
        raise newException(IOError, "websocket payload too large")

      realLen.int
    else: hdrLen

  f.masked = (b1 and 0x80) == 0x80
  if f.masked:
    f.maskingKey = await ws.recv(4, {})
  else:
    f.maskingKey = ""

  f.data = await ws.recv(finalLen, {})
  if f.data.len != finalLen: raise newException(IOError, "socket closed")

  if f.masked:
    unmask(f.data, f.maskingKey)

  result = f

proc extractCloseData*(data: string): tuple[code: int, reason: string] =
  ## A way to get the close code and reason out of the data of a Close opcode.
  var data = data
  result.code =
    if data.len >= 2:
      cast[ptr uint16](addr data[0])[].htons.int
    else:
      0
  result.reason = if data.len > 2: data[2..^1] else: ""

# Internal hashtable that tracks pings sent out, per socket.
# key is the socket fd
type PingRequest = Future[void] # tuple[data: string, fut: Future[void]]

when not defined(websocketIgnorePing):
  var reqPing {.threadvar.}: Option[Table[int, PingRequest]]

proc readData*(ws: AsyncSocket):
    Future[tuple[opcode: Opcode, data: string]] {.async.} =
  ## Reads reassembled data off the websocket and give you joined frame data.
  ##
  ## Note: You will still see control frames, but they are all handled for you
  ## (Ping/Pong, Cont, Close, and so on).
  ##
  ## The only ones you need to care about are Opcode.Text and Opcode.Binary, the
  ## so-called application frames.
  ##
  ## Will raise IOError when the socket disconnects and ProtocolError on any
  ## websocket-related issues.

  var resultData = ""
  var resultOpcode: Opcode

  when not defined(websocketIgnorePing):
    if reqPing.isNone:
      reqPing = some(initTable[int, PingRequest]())

    var pingTable = reqPing.unsafeGet()

  while true:
    let f = await ws.recvFrame()
    # Merge sequentially read frames.
    resultData.add(f.data)

    case f.opcode
    of Opcode.Ping:
      when not defined(websocketIgnorePing):
        await ws.send(makeFrame(Opcode.Pong, f.data))

    of Opcode.Pong:
      when not defined(websocketIgnorePing):
        if pingTable.hasKey(ws.getFD().AsyncFD.int):
          pingTable[ws.getFD().AsyncFD.int].complete()

    of Opcode.Cont:
      if not f.fin: continue

    of Opcode.Text, Opcode.Binary, Opcode.Close:
      resultOpcode = f.opcode
      # read another!
      if not f.fin: continue

    # handle case: ping never arrives and client closes the connection
    when not defined(websocketIgnorePing):
      if resultOpcode == Opcode.Close and pingTable.hasKey(ws.getFD().AsyncFD.int):
        let closeData = extractCloseData(resultData)
        let ex = newException(IOError, "socket closed while waiting for pong")
        if closeData.code != 0:
          ex.msg.add(", close code: " & $closeData.code)
        if closeData.reason != "":
          ex.msg.add(", reason: " & closeData.reason)
        pingTable[ws.getFD().AsyncFD.int].fail(ex)
        pingTable.del(ws.getFD().AsyncFD.int)

    return (resultOpcode, resultData)

proc sendText*(
  ws: AsyncSocket, p: string,
  maskingKey = generateMaskingKey()
): Future[void] {.async, deprecated: "Use the AsyncWebSocket variant instead".} =
  ## Sends text data. Will only return after all data has been sent out.
  await ws.send(makeFrame(Opcode.Text, p, maskingKey))

proc sendBinary*(
  ws: AsyncSocket, p: string, maskingKey = generateMaskingKey()
): Future[void] {.async, deprecated: "Use the AsyncWebSocket variant instead".} =
  ## Sends binary data. Will only return after all data has been sent out.
  await ws.send(makeFrame(Opcode.Binary, p, maskingKey))

proc sendPing*(
  ws: AsyncSocket, maskingKey = generateMaskingKey(), token: string = ""
): Future[void] {.async, deprecated: "Use the AsyncWebSocket variant instead".} =
  ## Sends a WS ping message.
  ## Will generate a suitable token if you do not provide one.

  let pingId = if token == "": $genOid() else: token
  await ws.send(makeFrame(Opcode.Ping, pingId, maskingKey))

proc sendChain*(ws: AsyncSocket, p: seq[string], opcode = Opcode.Text, maskingKeys: seq[string] = @[]): Future[void] {.async.} =
  ## Sends data over multiple frames. Will only return after all data has been sent out.
  for i, data in p:
    let maskKey = if i < maskingKeys.len: maskingKeys[i] else: generateMaskingKey()
    let f: Frame = (fin: i == p.high,
      rsv1: false, rsv2: false, rsv3: false,
      masked: maskKey.len != 0, maskingKey: maskKey,
      opcode: if i == 0: opcode else: Opcode.Cont,
      data: data)
    await ws.send(makeFrame(f))

proc readData*(ws: AsyncWebSocket): Future[tuple[opcode: Opcode, data: string]] =
  ## Reads reassembled data off the websocket and give you joined frame data.
  ##
  ## Note: You will still see control frames, but they are all handled for you
  ## (Ping/Pong, Cont, Close, and so on).
  ##
  ## The only ones you need to care about are Opcode.Text and Opcode.Binary, the
  ## so-called application frames.
  ##
  ## Will raise IOError when the socket disconnects and ProtocolError on any
  ## websocket-related issues.

  result = readData(ws.sock)

proc sendText*(ws: AsyncWebSocket, p: string, maskingKey = generateMaskingKey()): Future[void] =
  ## Sends text data. Will only return after all data has been sent out.
  let maskingKey =
    if ws.kind == Server: ""
    else: maskingKey
  result = ws.sock.send(makeFrame(Opcode.Text, p, maskingKey))

proc sendBinary*(ws: AsyncWebSocket, p: string, maskingKey = generateMaskingKey()): Future[void] =
  ## Sends binary data. Will only return after all data has been sent out.
  let maskingKey =
    if ws.kind == Server: ""
    else: maskingKey
  result = ws.sock.send(makeFrame(Opcode.Binary, p, maskingKey))

proc sendPing*(ws: AsyncWebSocket, maskingKey = generateMaskingKey(), token: string = "") {.async.} =
  ## Sends a WS ping message.
  ## Will generate a suitable token if you do not provide one.
  let maskingKey =
    if ws.kind == Server: ""
    else: maskingKey
  let pingId = if token == "": $genOid() else: token
  await ws.sock.send(makeFrame(Opcode.Ping, pingId, maskingKey))

proc closeWebsocket*(ws: AsyncSocket, code = 0, reason = ""): Future[void] {.async.} =
  ## Closes the socket.

  defer: ws.close()

  var data = newStringStream()

  if code != 0:
    data.write(code.uint16)

  if reason != "":
    data.write(reason)

  await ws.send(makeFrame(Opcode.Close, data.readAll()))

proc close*(ws: AsyncWebSocket, code = 0, reason = ""): Future[void] =
  ## Closes the socket.
  result = ws.sock.closeWebsocket(code, reason)

when isMainModule:
  block test1:
    let expected = "\129\139key1#\0\21]\4E.^\25\9\29"
    let got = makeFrame(Opcode.Text, "Hello World", "key1")
    doAssert expected == got

  block test2:
    let payload = repeat("Hello World", 10000)
    let got = makeFrame(Opcode.Text, payload, "key1")
    let expected = "\129\255\0\0\0\0\0\1\173\176key1#\0\21]\4E.^\25\9\29y\14\9\21^K2\22C\7"
    for i in 0 .. 34:
      doAssert got[i] == expected[i], "Not equal, " & $i & ", " & got[i].repr & " but wanted " & expected[i].repr