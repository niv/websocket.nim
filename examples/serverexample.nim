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
    while true:
      let (opcode, data) = await ws.readData()
      try:
        echo "(opcode: ", opcode, ", data length: ", data.len, ")"

        if opcode == Opcode.Text:
          waitFor ws.sendText("thanks for the data!")
        else:
          waitFor ws.sendBinary(data)
      except:
        echo getCurrentExceptionMsg()
        break

    asyncCheck ws.close()
    echo ".. socket went away."

waitFor server.serve(Port(8080), cb)