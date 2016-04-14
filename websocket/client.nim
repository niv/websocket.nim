## Example
## -------
##
## .. code-block::nim
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
  nativesockets, streams, tables, oids

import shared

import private/hex

type
  AsyncWebSocketObj = object of RootObj
    sock*: AsyncSocket

  AsyncWebSocket* = ref AsyncWebSocketObj

proc newAsyncWebsocket*(host: string, port: Port, path: string, ssl = false,
    additionalHeaders: seq[(string, string)] = @[]): Future[AsyncWebSocket] {.async.} =

  ## Create a new websocket and connect immediately.

  let key = encode($(getTime().int))

  let s = newAsyncSocket()
  if ssl:
    when not defined(ssl):
      raise newException(Exception, "Cannot connect over SSL without -d:ssl")
    else:
      let ctx = newContext(protTLSv1)
      ctx.wrapSocket(s)

  await s.connect(host, port)
  await s.send("GET " & path & " HTTP/1.1\r\n")
  await s.send("Host: " & host & "\r\n")
  await s.send("User-Agent: justatest\r\n")
  await s.send("Upgrade: websocket\r\n")
  await s.send("Connection: Upgrade\r\n")
  await s.send("Cache-Control: no-cache\r\n")
  await s.send("Sec-WebSocket-Key: " & key & "\r\n")
  await s.send("Sec-WebSocket-Version: 13\r\n")
  for h in additionalHeaders:
    await s.send(h[0] & ": " & h[1] & "\r\n")

  await s.send("\r\n")

  let hdr = await s.recvLine()
  if not hdr.startsWith("HTTP/1.1 101 "):
    s.close()
    raise newException(ProtocolError,
      "server did not reply with a websocket upgrade: " & hdr)

  while true:
    let ln = await s.recvLine()
    if ln == "\r\L": break
    let sp = ln.split(": ")
    if sp.len < 2: continue
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

  let ws = new AsyncWebSocket
  ws.sock = s
  result = ws

# proc sendFrameData(ws: AsyncWebSocket, data: string): Future[void] {.async.} =
#   await ws.sock.send(data)

proc close*(ws: AsyncWebSocket): Future[void] {.async.} =
  ## Closes the socket.

  defer: ws.sock.close()
  await ws.sock.send(makeFrame(Opcode.Close, "", true))

# proc readData(ws: AsyncWebSocket): auto {.async.} =
#   ## This is an alias for