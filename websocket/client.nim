## Example
## -------
##
## .. code-block::nim
##   import websocket, asyncnet, asyncdispatch
##
##   let ws = waitFor newAsyncWebsocketClient("localhost", Port(8080),
##     path = "/", protocols = @["myfancyprotocol"])
##   echo "connected!"
##
##   proc ping() {.async.} =
##     while true:
##       await sleepAsync(6000)
##       echo "ping"
##       await ws.sendPing()
##
##   proc read() {.async.} =
##     while true:
##       let (opcode, data) = await ws.readData()
##       echo "(opcode: ", opcode, ", data: ", data, ")"
##
##   asyncCheck read()
##   asyncCheck ping()
##   runForever()

import net, asyncdispatch, asyncnet, base64, times, strutils,
  nativesockets, streams, tables, oids, uri

when NimMinor < 18:
  import securehash
else:
  import std/sha1

import shared

import private/hex

const WebsocketUserAgent* = "websocket.nim (https://github.com/niv/websocket.nim)"

when not defined(ssl):
  type SslContext = ref object
var defaultSsl {.threadvar.}: SslContext

proc defaultSslContext: SslContext =
  result = defaultSsl
  when defined(ssl):
    if result.isNil:
      result = newContext(protTLSv1, verifyMode = CVerifyNone)
      doAssert(not result.isNil, "failure to initialize SSL context")
      defaultSsl = result

proc newAsyncWebsocketClient*(host: string, port: Port, path: string, ssl = false,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.async.} =
  ## Create a new websocket and connect immediately.
  ## Optionally give a list of protocols to negotiate; keep empty to accept the
  ## one the server offers (if any).
  ## The negotiated protocol is in `AsyncWebSocket.protocol`.

  let
    keyDec = align(
      when declared(toUnix):
        $getTime().toUnix
      else:
        $getTime().toSeconds.int64, 16, '#')
    key = encode(keyDec)
    s = newAsyncSocket()

  if ssl:
    when not defined(ssl):
      raise newException(Exception, "Cannot connect over SSL without -d:ssl")
    else:
      ctx.wrapSocket(s)

  await s.connect(host, port)
  var msg = "GET " & path & " HTTP/1.1\c\L"
  if port != Port(80):
    msg.add("Host: " & host & ":" & $port & "\c\L")
  else:
    msg.add("Host: " & host & "\c\L")
  msg.add("User-Agent: " & userAgent & "\c\L")
  msg.add("Upgrade: websocket\c\L")
  msg.add("Connection: Upgrade\c\L")
  msg.add("Cache-Control: no-cache\c\L")
  msg.add("Sec-WebSocket-Key: " & key & "\c\L")
  msg.add("Sec-WebSocket-Version: 13\c\L")
  if protocols.len != 0:
    msg.add("Sec-WebSocket-Protocol: " & protocols.join(", ") & "\c\L")
  for h in additionalHeaders:
    msg.add(h[0] & ": " & h[1] & "\c\L")
  msg.add("\c\L")

  await s.send(msg)

  let hdr = await s.recvLine()
  if not hdr.startsWith("HTTP/1.1 101 "):
    s.close()
    raise newException(ProtocolError,
      "server did not reply with a websocket upgrade: " & hdr)

  let ws = new AsyncWebSocket
  ws.kind = SocketKind.Client
  ws.sock = s

  while true:
    let ln = await s.recvLine()
    if ln == "\r\L": break
    let sp = ln.split(": ")
    if sp.len < 2: continue
    if sp[0].toLowerAscii == "sec-websocket-protocol":
      if protocols.len != 0 and protocols.find(sp[1]) == -1:
        raise newException(ProtocolError, "server does not support any of our protocols")
      else: ws.protocol = sp[1]

    # raise newException(ProtocolError, "unknown server response " & ln)
    if sp[0].toLowerAscii == "sec-websocket-accept":
      # The server appends the fixed string 258EAFA5-E914-47DA-95CA-C5AB0DC85B11
      # (a GUID) to the value from Sec-WebSocket-Key header (which is not decoded
      # from base64), applies the SHA-1 hashing function, and encodes the result
      # using base64.
      let theirs = sp[1]
      let expected = secureHash(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      if theirs != decodeHex($expected).encode:
        raise newException(ProtocolError, "websocket-key did not match. proxy messing with you?")

  result = ws

proc newAsyncWebsocketClient*(uri: Uri, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.async.} =

  var ssl: bool

  case uri.scheme
  of "ws":
    ssl = false
  of "wss":
    ssl = true
  else:
    raise newException(ProtocolError, "uri scheme has to be 'ws' for plaintext or 'wss' for websocket over ssl.")

  let port = Port(uri.port.parseInt())
  var path = uri.path
  if uri.query.len != 0:
    path.add('?')
    path.add(uri.query)
  result = await newAsyncWebsocketClient(uri.hostname, port, path, ssl,
    additionalHeaders, protocols, userAgent, ctx)

proc newAsyncWebsocketClient*(uri: string, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.async.} =
  let uriBuf = parseUri(uri)
  result = await newAsyncWebsocketClient(uriBuf, additionalHeaders, protocols, userAgent, ctx)

proc newAsyncWebsocket*(host: string, port: Port, path: string, ssl = false,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.deprecated.} =
  ## **Deprecated since 0.3.0**: Use `newAsyncWebsocketClient`:idx: instead.
  result = newAsyncWebsocketClient(host, port, path, ssl, additionalHeaders, protocols, userAgent, ctx)

proc newAsyncWebsocket*(uri: Uri, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.deprecated.} =
  ## **Deprecated since 0.3.0**: Use `newAsyncWebsocketClient`:idx: instead.
  result = newAsyncWebsocketClient(uri, additionalHeaders, protocols, userAgent, ctx)

proc newAsyncWebsocket*(uri: string, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.deprecated.} =
  ## **Deprecated since 0.3.0**: Use `newAsyncWebsocketClient`:idx: instead.
  result = newAsyncWebsocketClient(uri, additionalHeaders, protocols, userAgent, ctx)