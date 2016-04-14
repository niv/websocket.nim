## Example
## -------
##
## .. code-block::nim
##   var server = newAsyncHttpServer()
##
##   proc cb(req: Request) {.async.} =
##     handleWebsocketRequest(req):
##       echo "New websocket customer!"
##
##       while true:
##         try:
##           var f = await req.client.readData()
##           echo f
##         except ProtocolError, IOError:
##           break
##
##       echo "Socket went away"
##       req.client.close()

import asyncnet, asyncdispatch, asynchttpserver, strtabs, base64, securehash

import shared


template handleWebsocketRequest*(req: Request, body: stmt): stmt {.immediate.} =
  ## Does all the websockety connection upgrade for you.
  ## Will respond with Http400 and close the socket if the request is not
  ## from a websocket endpoint.

  if not req.headers.hasKey("sec-websocket-key"):
    waitFor req.respond(Http400, "This is a websocket endpoint.")
    req.client.close

  else:
    let sh = secureHash(req.headers["sec-websocket-key"] &
      "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    let acceptKey = decodeHex($sh).encode

    waitFor req.client.send("HTTP/1.1 101 Web Socket Protocol Handshake\c\L")
    waitFor req.client.send("Sec-Websocket-Accept: " & acceptKey & "\c\L")
    waitFor req.client.send("Connection: Upgrade\c\L")
    waitFor req.client.send("Upgrade: websocket\c\L")
    waitFor req.client.send("\c\L")

    body



# proc respondWithWebsocket(req: Request)