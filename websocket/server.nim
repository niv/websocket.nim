## Example
## -------
##
## .. code-block::nim
##   import websocket, asynchttpserver, asyncnet, asyncdispatch
##
##   let server = newAsyncHttpServer()
##   proc cb(req: Request) {.async.} =
##
##     let (ws, error) = await verifyWebsocketRequest(req, "myfancyprotocol")
##
##     if ws.isNil:
##       echo "WS negotiation failed: ", error
##       await req.respond(Http400, "Websocket negotiation failed: " & error)
##       req.client.close()
##
##     else:
##       echo "New websocket customer arrived!"
##       waitFor ws.read(proc (opcode: Opcode, data: string): bool {.async.} =
##         try:
##           echo "(opcode: ", opcode, ", data: ", data.len, ")"
##
##           if opcode == Opcode.Text:
##             waitFor ws.sendText("thanks for the data!")
##           else:
##             waitFor ws.sendBinary(data)
##         except:
##           echo getCurrentExceptionMsg()
##           result = true)
##
##       asyncCheck ws.close()
##       echo ".. socket went away."
##
##   waitFor server.serve(Port(8080), cb)

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
  
  template reterr(err: string) =
    result.error = err
    return

  # if req.headers.hasKey("sec-websocket-extensions"):
    # TODO: transparently support extensions

  if req.headers.getOrDefault("sec-websocket-version") != "13":
    reterr "the only supported sec-websocket-version is 13"

  if not req.headers.hasKey("sec-websocket-key"):
    reterr "no sec-websocket-key provided"

  let isProtocolEmpty = protocol == ""

  if req.headers.hasKey("sec-websocket-protocol"):
    if isProtocolEmpty:
      reterr "server does not support protocol negotation"

    block protocolCheck:
      let prot = protocol.toLowerAscii()

      for it in req.headers["sec-websocket-protocol"].split(", "):
        if prot == it.strip.toLowerAscii():
          break protocolCheck
      
      reterr "no advertised protocol supported; server speaks `" & protocol & "`" 
  elif not isProtocolEmpty:
    reterr "no protocol advertised, but server demands `" & protocol & "`"

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

  new(result.ws)
  result.ws.kind = SocketKind.Server
  result.ws.sock = req.client
  result.ws.protocol = protocol

  result.error = ""
