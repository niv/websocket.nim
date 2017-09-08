## Example
## -------
##
## .. code-block::nim
##   import websocket, asyncnet, asyncdispatch
##
##   let ws = waitFor newAsyncWebsocket("echo.websocket.org",
##     Port 80, "/?encoding=text", ssl = false)
##   echo "connected!"
##
##   proc reader() {.async.} =
##     while true:
##       let read = await ws.sock.readData(true)
##       echo "read: " & $read
##
##   proc ping() {.async.} =
##     while true:
##       await sleepAsync(6000)
##       echo "ping"
##       await ws.sock.sendPing(true)
##
##   asyncCheck reader()
##   asyncCheck ping()
##   runForever()

import net, asyncdispatch, asyncnet, base64, times, strutils, securehash,
  nativesockets, streams, tables, oids, uri

import shared

import private/hex

const WebsocketUserAgent* = "websocket.nim (https://github.com/niv/websocket.nim)"

proc newAsyncWebsocket*(host: string, port: Port, path: string, ssl = false,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    verifySsl: bool = true 
   ): Future[AsyncWebSocket] {.async.} =
  ## Create a new websocket and connect immediately.
  ## Optionally give a list of protocols to negotiate; keep empty to accept the
  ## one the server offers (if any).
  ## The negotiated protocol is in `AsyncWebSocket.protocol`.

  let key = encode($(getTime().int))

  let s = newAsyncSocket()
  if ssl:
    when not defined(ssl):
      raise newException(Exception, "Cannot connect over SSL without -d:ssl")
    else:
      if verifySsl:
        let ctx = newContext(protTLSv1)
        ctx.wrapSocket(s)
      else: 
        let ctx = newContext(protTLSv1, verifyMode = CVerifyNone)
        ctx.wrapSocket(s)

  await s.connect(host, port)
  await s.send("GET " & path & " HTTP/1.1\c\L")
  if port != Port(80) or port != Port(443):
    await s.send("Host: " & host & ":" & $port & "\c\L")
  else:
    await s.send("Host: " & host & "\c\L")
  await s.send("User-Agent: " & userAgent & "\c\L")
  await s.send("Upgrade: websocket\c\L")
  await s.send("Pragma: no-cache\c\L")
  await s.send("Connection: Upgrade\c\L")
  await s.send("Cache-Control: no-cache\c\L")
  await s.send("Sec-WebSocket-Key: " & key & "\c\L")
  await s.send("Sec-WebSocket-Version: 13\c\L")
  await s.send("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\c\L")
  if protocols.len > 0:
    await s.send("Sec-WebSocket-Protocol: " & protocols.join(", ") & "\c\L")
  for h in additionalHeaders:
    await s.send(h[0] & ": " & h[1] & "\c\L")

  await s.send("\c\L")

  let hdr = await s.recvLine()
  if not hdr.startsWith("HTTP/1.1 101 "):
    s.close()
    raise newException(ProtocolError,
      "server did not reply with a websocket upgrade: " & hdr)

  let ws = new AsyncWebSocket
  ws.sock = s
  ws.isClient = true

  while true:
    let ln = await s.recvLine()
    if ln == "\r\L": break
    let sp = ln.split(": ")
    echo(sp)
    if sp.len < 2: continue
    if sp[0].toLower == "sec-websocket-protocol":
      if protocols.len > 0 and protocols.find(sp[1]) == -1:
        raise newException(ProtocolError, "server does not support any of our protocols")
      else: ws.protocol = sp[1]

    # raise newException(ProtocolError, "unknown server response " & ln)
    if sp[0].toLower == "sec-websocket-accept":
      # The server appends the fixed string 258EAFA5-E914-47DA-95CA-C5AB0DC85B11
      # (a GUID) to the value from Sec-WebSocket-Key header (which is not decoded
      # from base64), applies the SHA-1 hashing function, and encodes the result
      # using base64.
      let theirs = sp[1]
      let expected = secureHash(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      if theirs != decodeHex($expected).encode:
        raise newException(ProtocolError, "websocket-key did not match. proxy messing with you?")

  return ws

proc newAsyncWebsocket*(uri: Uri, additionalHeaders: seq[(string, string)] = @[], 
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    verifySsl: bool = true 
   ): Future[AsyncWebSocket] {.async.} =
  var ssl: bool
  if uri.scheme == "ws":
    ssl = false
  elif uri.scheme == "wss":
    ssl = true
  else:
    raise newException(ProtocolError, "uri scheme has to be 'ws' for plaintext or 'wss' for websocket over ssl.")
  
  var port: Port
  if uri.port == "":
    if ssl: 
      port = 443.Port 
    else: 
      port = 80.Port 
  else: 
    port = Port(uri.port.parseInt())
      
  return await newAsyncWebsocket(uri.hostname, port , uri.path, ssl,
    additionalHeaders, protocols, userAgent, verifySsl)
  
proc newAsyncWebsocket*(uri: string, additionalHeaders: seq[(string, string)] = @[], 
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    verifySsl: bool = true 
   ): Future[AsyncWebSocket] {.async.} =
  let uriBuf = parseUri(uri)
  return await newAsyncWebsocket(uriBuf, additionalHeaders, protocols, userAgent, verifySsl)

# proc sendFrameData(ws: AsyncWebSocket, data: string): Future[void] {.async.} =
#   await ws.sock.send(data)

proc close*(ws: AsyncWebSocket): Future[void] {.async.} =
  ## Closes the socket.

  defer: ws.sock.close()
  var se = makeFrame(Opcode.Close, "", true)
  await ws.sock.send(se[0].addr, se.len)

# proc readData(ws: AsyncWebSocket): auto {.async.} =
#   ## This is an alias for
