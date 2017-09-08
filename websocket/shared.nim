import asyncdispatch, asyncnet, streams, nativesockets, strutils, tables,
  times, oids, random

type
  ProtocolError* = object of Exception

  Opcode* {.pure.} = enum
    ##
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
                 ## Do not mask data yourself.

    opcode: Opcode ## The opcode of this frame.

    data: seq[char] ## App data

  WSError* = object of IOError 
    closeCode*: int 
  
  AsyncWebSocketObj = object of RootObj
    sock*: AsyncSocket
    protocol*: string
    isClient: bool

  AsyncWebSocket* = ref AsyncWebSocketObj

proc htonl2(x: uint64): uint64 =
  ## Converts 64-bit unsigned integers from network to host byte order.
  ## On machines where the host byte order is the same as network byte order,
  ## this is a no-op; otherwise, it performs a 8-byte swap operation.
  when cpuEndian == bigEndian: result = x
  else: result = (x shr 56'u64) or
                 (x shl 40'u64 and 0x00FF000000000000'u64) or
                 (x shl 24'u64 and 0x0000FF0000000000'u64) or
                 (x shl 8'u64 and 0x000000FF00000000'u64) or
                 (x shr 8'u64 and 0x00000000FF000000'u64) or
                 (x shr 24'u64 and 0x0000000000FF0000'u64) or
                 (x shr 40'u64 and 0x000000000000FF00'u64) or
                 (x shl 56'u64)


proc asString*(data: seq[char]) : string = 
  cast[string](data)


proc makeFrame*(f: Frame): seq[char] =
  ## Generate valid websocket frame data, ready to be sent over the wire.
  ## This is useful for rolling your own impl, for example
  ## with AsyncHttpServer

  result = newSeq[char]()

  var b0: byte = f.opcode.byte
  if f.fin: b0 = b0 or 0x80
  result.add(b0.char)

  var b1: byte = 0
  if f.masked: b1 = 0x80 

  if f.data.len < 126:
    result.add((b1 or f.data.len.byte).char)
  elif f.data.len <= 65536: 
    result.add((b1 or 126).char)
    var len = f.data.len.uint16.htons
    result.add(cast[ptr array[2, char]](len.addr)[])
  else: 
    result.add((b1 or 127).char)
    var len = f.data.len.uint64.htonl2
    result.add(cast[ptr array[8, char]](len.addr)[])

  if f.masked: 
    randomize()
    let maskingKey = [ random(256).char, random(256).char,
                       random(256).char, random(256).char ]
    result.add(maskingKey)
    var tmp: seq[char]
    shallowCopy tmp, f.data 
    for i in 0..<tmp.len: tmp[i] = (tmp[i].uint8 xor maskingKey[i mod 4].uint8).char
    result.add(tmp)
  else: 
    result.add(f.data)


proc makeFrame*(opcode: Opcode, data: string, masked: bool): seq[char] =
  ## A convenience shorthand.
  result = makeFrame((fin: true, rsv1: false, rsv2: false, rsv3: false,
    masked: masked, opcode: opcode, data: cast[seq[char]](data)))

proc makeFrame*(opcode: Opcode, data: seq[char], masked: bool): seq[char] =
  ## A convenience shorthand.
  result = makeFrame((fin: true, rsv1: false, rsv2: false, rsv3: false,
    masked: masked, opcode: opcode, data: data))


proc recvFrame*(ws: AsyncSocket): Future[Frame] {.async.} =
  ## Read a full frame off the given socket.
  ##
  ## You probably want to use the higher-level variant, `readData`.
  template `[]`(b: byte, idx: int): bool =
    const lookupTable = [128u8, 64, 32, 16, 8, 4, 2, 1]
    (b and lookupTable[idx]) != 0

  if ws.isClosed():
    raise newException(WSError, "can't read from closed connection")

  
  var f: Frame
  var data2 = newSeq[char](2) #first half of the header, and 2nd half
  var data8 = newSeq[char](8) #used for extended payload length
  var maskKey = newSeq[char](4) #used for maskKey 
  var read: int #control variable used to control read bytes from socket
  read = await ws.recvInto(addr(data2[0]), 2)
  assert(read == 2, "could not read 2 bytes from socket, trying to read frameheader")

  f.fin = (data2[0].uint8 and 0x80) == 0x80 #check first bit for fin flag
  f.rsv1 = (data2[0].uint8 and 0x40) == 0x40 
  f.rsv2 = (data2[0].uint8 and 0x20) == 0x20 
  f.rsv3 = (data2[0].uint8 and 0x10) == 0x10 
  f.opcode = (data2[0].uint8 and 0xf).Opcode #check last 4 bits of the first byte for opcode
  #TODO check 2nd, 3rd, 4th bit; see if extension gives it meaning for now we just close the conn
  if f.rsv1 or f.rsv2 or f.rsv3: 
    #TODO await ws.send(close reason and message as seq[char]?)
    raise newException(ProtocolError,
      "websocket tried to use non-negotiated extension")
  # if true throw exception and close connection
  f.masked = (data2[1].uint8 and 0x80) == 0x80 #check 9th bit to see if the message is masked

  var size: uint64 = data2[1].uint8 and 0x7f #check the next 7bit to get the length
  if size == 126: 
    read = await ws.recvInto(addr(data2[0]), 2)
    assert(read == 2, "could not read 2 bytes from socket, trying to read 16bit length")
    size = cast[ptr uint16](data2[0].addr)[].htons
  elif size == 127:
    read = await ws.recvInto(addr(data8[0]), 8)
    assert(read == 8, "could not read 8 bytes from socket, trying to read 64bit length")
    size = cast[ptr uint64](data8[0].addr)[].htonl2

  if f.masked: 
    read = await ws.recvInto(addr(maskKey), 4)
    assert(read == 4, "could not read 4 bytes from socket, trying to read maskedKey")
  
  f.data = newSeq[char](size)
  #TODO only int allowed, uint64 bigger than int 
  #check int.max against size, read until int reached uint64 size?
  read = await ws.recvInto(addr(f.data[0]), size.int)
  for i in 0..<f.data.len: f.data[i] = (f.data[i].uint8 xor maskKey[i mod 4].uint8).char

  result = f

# Internal hashtable that tracks pings sent out, per socket.
# key is the socket fd
type PingRequest = Future[void] # tuple[data: string, fut: Future[void]]
var reqPing {.threadvar.}: Table[int, PingRequest]
reqPing = initTable[int, PingRequest]()

proc readData*(ws: AsyncSocket, isClientSocket: bool):
    Future[tuple[opcode: Opcode, data: seq[char]]] {.async.} =

  ## Reads reassembled data off the websocket and give you joined frame data.
  ##
  ## Note: You will still see control frames, but they are all handled for you
  ## (Ping/Pong, Cont, Close, and so on).
  ##
  ## The only ones you need to care about are Opcode.Text and Opcode.Binary, the
  ## so-called application frames.
  ##
  ## As per the websocket specifications, all clients need to mask their responses.
  ## It is up to you to to set `isClientSocket` with a proper value, depending on
  ## if you are reading from a server or client socket.
  ##
  ## Will raise IOError when the socket disconnects and ProtocolError on any
  ## websocket-related issues.

  var resultData = newSeq[char]()
  var resultOpcode: Opcode
  while true:
    let f = await ws.recvFrame()
    # Merge sequentially read frames.
    resultData &= f.data

    case f.opcode
      of Opcode.Close:
        var tmp: seq[char]
        shallowCopy tmp, f.data
        # handle case: ping never arrives and client closes the connection
        let ex = newException(WSError, "socket closed by remote peer")
        ex.closeCode = cast[ptr uint16](tmp[0].addr)[].htons.int
        # TODO read rest of messag eif bigger than 2 

        if reqPing.hasKey(ws.getFD().AsyncFD.int):
          reqPing[ws.getFD().AsyncFD.int].fail(ex)
          reqPing.del(ws.getFD().AsyncFD.int)

        raise ex

      of Opcode.Ping:
        var se = makeFrame(Opcode.Pong, f.data, isClientSocket)
        await ws.send(se[0].addr, se.len)

      of Opcode.Pong:
        if reqPing.hasKey(ws.getFD().AsyncFD.int):
          reqPing[ws.getFD().AsyncFD.int].complete()

        else: discard  # thanks, i guess?

      of Opcode.Cont:
        if not f.fin: continue

      of Opcode.Text, Opcode.Binary:
        resultOpcode = f.opcode
        # read another!
        if not f.fin: continue

      else:
        ws.close()
        raise newException(ProtocolError, "received invalid opcode: " & $f.opcode)

    result = (resultOpcode, resultData)
    return

proc sendText*(ws: AsyncSocket, p: string, masked: bool): Future[void] {.async.} =
  ## Sends text data. Will only return after all data has been sent out.
  var se = makeFrame(Opcode.Text, p, masked)
  await ws.send(se[0].addr, se.len)

proc sendText*(ws: AsyncWebsocket, p: string): Future[void] {.async.} = 
  var se = makeFrame(Opcode.Text, p, true)
  await ws.sock.send(se[0].addr, se.len)

proc sendBinary*(ws: AsyncSocket, p: string, masked: bool): Future[void] {.async.} =
  ## Sends binary data. Will only return after all data has been sent out.
  var se = makeFrame(Opcode.Binary, p, masked)
  await ws.send(se[0].addr, se.len)

proc sendBinary*(ws: AsyncWebsocket, p: string): Future[void] {.async.} = 
  var se = makeFrame(Opcode.Binary, p, true)
  await ws.sock.send(se[0].addr, se.len)

proc sendBinary*(ws: AsyncWebsocket, p: seq[char]): Future[void] {.async.} = 
  var se = makeFrame(Opcode.Binary, p, true)
  await ws.sock.send(se[0].addr, se.len)

proc sendPing*(ws: AsyncSocket, masked: bool, token: string = ""): Future[void] {.async.} =
  ## Sends a WS ping message.
  ## Will generate a suitable token if you do not provide one.

  let pingId = if token == "": $genOid() else: token
  var se = makeFrame(Opcode.Ping, pingId, masked)
  await ws.send(se[0].addr, se.len)
