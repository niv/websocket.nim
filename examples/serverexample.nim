import ../websocket, asynchttpserver, asyncnet, asyncdispatch

let server = newAsyncHttpServer()
proc cb(req: Request) {.async.} =

  let (ws, error) = await verifyWebsocketRequest(req, "myfancyprotocol")

  if ws.isNil:
    echo "WS negotiation failed: ", error
    await req.respond(Http400, "Websocket negotiation failed: " & error)
    req.client.close()

  else:
    echo "New websocket customer arrived!"
    waitFor ws.read(proc (opcode: Opcode, data: string): Future[bool] {.async.} =
      try:
        echo "(opcode: ", opcode, ", data: ", data.len, ")"

        if opcode == Opcode.Text:
          waitFor ws.sendText("thanks for the data!")
        else:
          waitFor ws.sendBinary(data)
      except:
        echo getCurrentExceptionMsg()
        result = true)

    asyncCheck ws.close()
    echo ".. socket went away."

waitFor server.serve(Port(8080), cb)
