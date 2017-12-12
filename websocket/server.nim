## Example
## -------
##
## .. code-block::nim
##   import websocket, asynchttpserver, asyncnet, asyncdispatch
##
##   var server = newAsyncHttpServer()
##   proc cb(req: Request) {.async.} =
##
##     let (success, error) = await(verifyWebsocketRequest(req, "myfancyprotocol"))
##     if not success:
##       echo "WS negotiation failed: " & error
##       await req.respond(Http400, "Websocket negotiation failed: " & error)
##       req.client.close
##
##     else:
##       echo "New websocket customer arrived!"
##       while true:
##         try:
##           var f = await req.client.readData(false)
##           echo "(opcode: " & $f.opcode & ", data: " & $f.data.len & ")"
##
##           if f.opcode == Opcode.Text:
##             waitFor req.client.sendText("thanks for the data!", false)
##           else:
##             waitFor req.client.sendBinary(f.data, false)
##
##         except:
##           echo getCurrentExceptionMsg()
##           break
##
##       req.client.close()
##       echo ".. socket went away."

import asyncnet, asyncdispatch, asynchttpserver, strtabs, base64, securehash,
  strutils, sequtils

import private/hex

import shared

proc verifyWebsocketRequest*(req: Request, protocol = ""):
    Future[tuple[valid: bool, error: string]] {.async.} =

  ## Verifies the request is a websocket request:
  ## * Supports protocol version 13 only
  ## * Does not support extensions (yet)
  ## * Will auto-negotiate a compatible protocol based on your `protocol` param
  ##
  ## If all validations pass, will give you a tuple (true, "").
  ## You can pass in a empty protocol param to not perform negotiation; this is
  ## the equivalent of accepting all protocols the client might request.
  ##
  ## If the client does not send any protocols, but you have given one, the
  ## request will fail.
  ##
  ## If validation FAILS, the response will be (false, human-readable failure reason).
  ##
  ## After successful negotiation, you can immediately start sending/reading
  ## websocket frames.

  if req.headers.hasKey("sec-websocket-extensions"):
    # TODO: transparently support extensions
    discard

  if req.headers.getOrDefault("sec-websocket-version") != "13":
    result = (false, "the only supported sec-websocket-version is 13")
    return

  if not req.headers.hasKey("sec-websocket-key"):
    result = (false, "no sec-websocket-key provided")
    return

  let cliWantsProt = req.headers.hasKey("sec-websocket-protocol")

  if cliWantsProt and protocol == "":
    result = (false, "server does not support protocol negotiation")
    return

  if not cliwantsProt and protocol != "":
    result = (false, "no protocol advertised, but server demands `" & protocol & "`")
    return

  if cliwantsProt and protocol != "":
    let wants = req.headers["sec-websocket-protocol"].split(",").
      mapIt(it.strip.tolower)

    if wants.find(protocol.tolower) == -1:
      result = (false, "no advertised protocol supported; server speaks `" & $protocol & "`" )
      return

  let sh = secureHash(req.headers["sec-websocket-key"] &
    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  let acceptKey = decodeHex($sh).encode
  var msg = "HTTP/1.1 101 Web Socket Protocol Handshake\c\L"
  msg.add("Sec-Websocket-Accept: " & acceptKey & "\c\L")
  msg.add("Connection: Upgrade\c\L")
  msg.add("Upgrade: websocket\c\L")
  if protocol != "": msg.add("Sec-Websocket-Protocol: " & protocol & "\c\L")
  msg.add "\c\L"
  await req.client.send(msg)

  result = (true, "")
