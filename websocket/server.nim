## Example
## -------
##
## .. code-block::nim
##   import websocket, asynchttpserver, asyncnet, asyncdispatch
##
##   var server = newAsyncHttpServer()
##   proc cb(req: Request) {.async.} =
##
##     let (ws, error) = await(verifyWebsocketRequest(req, "myfancyprotocol"))
##     if ws.isNil:
##       echo "WS negotiation failed: ", error
##       await req.respond(Http400, "Websocket negotiation failed: " & error)
##       req.client.close()
##
##     else:
##       echo "New websocket customer arrived!"
##       while true:
##         try:
##           var f = await ws.readData()
##           echo "(opcode: ", f.opcode, ", data: ", f.data.len, ")"
##
##           if f.opcode == Opcode.Text:
##             waitFor ws.sendText("thanks for the data!", masked = false)
##           else:
##             waitFor ws.sendBinary(f.data, masked = false)
##
##         except:
##           echo getCurrentExceptionMsg()
##           break
##
##       ws.close()
##       echo ".. socket went away."
##
##   waitfor server.serve(Port(8080), cb)

import asyncnet, asyncdispatch, asynchttpserver, strtabs, base64, securehash,
  strutils, sequtils

import private/hex

import shared

proc verifyWebsocketRequest*(req: Request, protocol = ""):
    Future[tuple[ws: AsyncWebSocket, error: string]] {.async.} =

  ## Verifies the request is a websocket request:
  ## * Supports protocol version 13 only
  ## * Does not support extensions (yet)
  ## * Will auto-negotiate a compatible protocol based on your `protocol` param
  ##
  ## If all validations pass, will give you a tuple (AsyncWebSocket, "").
  ## You can pass in a empty protocol param to not perform negotiation; this is
  ## the equivalent of accepting all protocols the client might request.
  ##
  ## If the client does not send any protocols, but you have given one, the
  ## request will fail.
  ##
  ## If validation FAILS, the response will be (nil, human-readable failure reason).
  ##
  ## After successful negotiation, you can immediately start sending/reading
  ## websocket frames.

  # if req.headers.hasKey("sec-websocket-extensions"):
    # TODO: transparently support extensions

  if req.headers.getOrDefault("sec-websocket-version") != "13":
    result.error = "the only supported sec-websocket-version is 13"
    return

  if not req.headers.hasKey("sec-websocket-key"):
    result.error = "no sec-websocket-key provided"
    return

  let isProtocolEmpty = protocol == ""

  if req.headers.hasKey("sec-websocket-protocol"):
    if isProtocolEmpty:
      result.error = "server does not support protocol negotation"
      return

    block protocolCheck:
      let prot = protocol.toLowerAscii()

      for it in req.headers["sec-websocket-protocol"].split(", "):
        if prot == it.strip.toLowerAscii():
          break protocolCheck
      
      result.error = "no advertised protocol supported; server speaks `" & protocol & "`" 
      return
  elif not isProtocolEmpty:
    result.error = "no protocol advertised, but server demands `" & protocol & "`"
    return

  let sh = secureHash(req.headers["sec-websocket-key"] &
    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  let acceptKey = decodeHex($sh).encode
  var msg = "HTTP/1.1 101 Web Socket Protocol Handshake\c\L"
  msg.add("Sec-Websocket-Accept: " & acceptKey & "\c\L")
  msg.add("Connection: Upgrade\c\L")
  msg.add("Upgrade: websocket\c\L")
  if not isProtocolEmpty: msg.add("Sec-Websocket-Protocol: " & protocol & "\c\L")
  msg.add "\c\L"
  await req.client.send(msg)

  let ws = new AsyncWebSocket
  ws.kind = SocketKind.Server
  ws.sock = req.client

  result = (ws, "")
