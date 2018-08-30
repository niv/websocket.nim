## Example
## -------
##
## .. code-block::nim
##   import websocket, asynchttpserver, asyncnet, asyncdispatch
##
##   let server = newAsyncHttpServer()
##
##   proc cb(req: Request) {.async.} =
##     let (ws, error) = await verifyWebsocketRequest(req, "myfancyprotocol")
##
##     if ws.isNil:
##       echo "WS negotiation failed: ", error
##       await req.respond(Http400, "Websocket negotiation failed: " & error)
##       req.client.close()
##       return
##
##     echo "New websocket customer arrived!"
##     while true:
##       let (opcode, data) = await ws.readData()
##       try:
##         echo "(opcode: ", opcode, ", data length: ", data.len, ")"
##
##         case opcode
##         of Opcode.Text:
##           waitFor ws.sendText("thanks for the data!")
##         of Opcode.Binary:
##           waitFor ws.sendBinary(data)
##         of Opcode.Close:
##           asyncCheck ws.close()
##           let (closeCode, reason) = extractCloseData(data)
##           echo "socket went away, close code: ", closeCode, ", reason: ", reason
##         else: discard
##       except:
##         echo "encountered exception: ", getCurrentExceptionMsg()
##
##   waitFor server.serve(Port(8080), cb)

import asyncnet, asyncdispatch, asynchttpserver, strtabs, base64,
  strutils, sequtils

when NimMinor < 18:
  import securehash
else:
  import std/sha1

import private/hex

import shared

proc makeHandshakeResponse*(key, protocol: string): string =
  let sh = secureHash(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  let acceptKey = decodeHex($sh).encode

  result = "HTTP/1.1 101 Web Socket Protocol Handshake\c\L"
  result.add("Sec-Websocket-Accept: " & acceptKey & "\c\L")
  result.add("Connection: Upgrade\c\L")
  result.add("Upgrade: websocket\c\L")
  if protocol.len != 0:
    result.add("Sec-Websocket-Protocol: " & protocol & "\c\L")
  result.add "\c\L"

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

  template reterr(err: untyped) =
    result.error = err
    return

  # if req.headers.hasKey("sec-websocket-extensions"):
    # TODO: transparently support extensions

  if req.headers.getOrDefault("sec-websocket-version") != "13":
    reterr "the only supported sec-websocket-version is 13"

  if not req.headers.hasKey("sec-websocket-key"):
    reterr "no sec-websocket-key provided"

  if req.headers.hasKey("sec-websocket-protocol"):
    if protocol.len == 0:
      reterr "server does not support protocol negotation"

    block protocolCheck:
      let prot = protocol.toLowerAscii()

      for it in req.headers["sec-websocket-protocol"].split(','):
        if prot == it.strip.toLowerAscii():
          break protocolCheck

      reterr "no advertised protocol supported; server speaks `" & protocol & "`"
  elif protocol.len != 0:
    reterr "no protocol advertised, but server demands `" & protocol & "`"

  let msg = makeHandshakeResponse(req.headers["sec-websocket-key"], protocol)
  await req.client.send(msg)

  new(result.ws)
  result.ws.kind = SocketKind.Server
  result.ws.sock = req.client
  result.ws.protocol = protocol

  result.error = ""
