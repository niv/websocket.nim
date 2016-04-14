## Example
## -------
##
## .. code-block::nim
##   var server = newAsyncHttpServer()
##
##   if not await(verifyWebsocketRequest(req)):
##     await req.respond(Http400, "This is a websocket endpoint.")
##     req.client.close
##
##   else:
##     echo "New websocket customer arrived!"
##     while true:
##       try:
##         var f = await req.client.readData(false)
##         echo f
##         await req.client.sendText("thanks for the data!", false)
##
##       except ProtocolError, IOError:
##         echo getCurrentExceptionMsg()
##         break
##
##     req.client.close()
##     echo ".. socket went away."

import asyncnet, asyncdispatch, asynchttpserver, strtabs, base64, securehash

import private/hex

import shared

proc verifyWebsocketRequest*(req: Request): Future[bool] {.async.} =
  ## Verifies the request is a websocket request. If so, it sends out the
  ## connection upgrade magic for you; leaving the socket in a state where
  ## you can immediately start receiving/sending frames.

  if not req.headers.hasKey("sec-websocket-key"):
    result = false
    # await req.respond(Http400, "This is a websocket endpoint.")
    # req.client.close

  else:
    let sh = secureHash(req.headers["sec-websocket-key"] &
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    let acceptKey = decodeHex($sh).encode

    await req.client.send("HTTP/1.1 101 Web Socket Protocol Handshake\c\L")
    await req.client.send("Sec-Websocket-Accept: " & acceptKey & "\c\L")
    await req.client.send("Connection: Upgrade\c\L")
    await req.client.send("Upgrade: websocket\c\L")
    await req.client.send("\c\L")

    result = true

