## Example
## -------
##
## .. code-block::nim
##   import websocket, asyncnet, asyncdispatch
##
##   let ws = waitFor newAsyncWebsocketClient("localhost", Port(8080),
##     path = "/", protocols = @["myfancyprotocol"])
##   echo "connected!"
##
##   proc ping() {.async.} =
##     while true:
##       await sleepAsync(6000)
##       echo "ping"
##       await ws.sendPing()
##
##   proc read() {.async.} =
##     while true:
##       let (opcode, data) = await ws.readData()
##       echo "(opcode: ", opcode, ", data: ", data, ")"
##
##   asyncCheck read()
##   asyncCheck ping()
##   runForever()

import net, asyncdispatch, asyncnet, base64,
  times, strutils, nativesockets, uri

import httpclient except ProtocolError

import shared

const WebsocketUserAgent* = "websocket.nim (https://github.com/niv/websocket.nim)"

when not declared(httpclient.getDefaultSsl):
  when not defined(ssl):
    type SslContext = ref object
  var defaultSsl {.threadvar.}: SslContext

  proc getDefaultSsl: SslContext =
    result = defaultSsl
    when defined(ssl):
      if result.isNil:
        result = newContext(protTLSv1, verifyMode = CVerifyNone)
        doAssert(not result.isNil, "failure to initialize SSL context")
        defaultSsl = result

proc newAsyncWebsocketClient*(uri: Uri, client: AsyncHttpClient,
    protocols: seq[string] = @[]): Future[AsyncWebSocket] {.async.} =
  ## Create a new websocket and connect immediately.
  ## Optionally give a list of protocols to negotiate; keep empty to accept the
  ## one the server offers (if any).
  ## The negotiated protocol is in `AsyncWebSocket.protocol`.

  let
    keyDec = align(
      when declared(toUnix):
        $getTime().toUnix
      else:
        $getTime().toSeconds.int64, 16, '#')
    key = encode(keyDec)

  var uri = uri
  case uri.scheme # this is scummy
  of "ws":
    uri.scheme = "http"
  of "wss":
    uri.scheme = "https"
  else:
    raise newException(ProtocolError, "uri scheme has to be " &
      "'ws' for plaintext or 'wss' for websocket over ssl.")

  var headers = newHttpHeaders({
    "Connection": "Upgrade",
    "Upgrade": "websocket",
    "Cache-Control": "no-cache",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": key
  })
  if protocols.len != 0:
    headers["Sec-WebSocket-Protocol"] = protocols.join(", ")
  let resp = await client.request($uri, "GET", headers = headers)
  if resp.code != Http101:
    client.getSocket().close()
    raise newException(ProtocolError,
      "Server did not reply with a websocket upgrade: " & $resp.code)

  new(result)
  result.kind = SocketKind.Client
  result.sock = client.getSocket()

proc newAsyncWebsocketClient*(uri: Uri,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    sslContext: SslContext = getDefaultSsl()
   ): Future[AsyncWebSocket] =
  let client =
    when defined(ssl):
      newAsyncHttpClient(userAgent = userAgent, sslContext = sslContext)
    else:
      newAsyncHttpClient(userAgent = userAgent)
  client.headers = newHttpHeaders(additionalHeaders)
  result = newAsyncWebsocketClient(uri, client, protocols)

proc newAsyncWebsocketClient*(uri: string,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    sslContext: SslContext = getDefaultSsl()
   ): Future[AsyncWebSocket] =
  result = newAsyncWebsocketClient(parseUri(uri),
    additionalHeaders, protocols, userAgent, sslContext)

proc newAsyncWebsocketClient*(host: string, port: Port, path: string,
    ssl = false, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    sslContext: SslContext = getDefaultSsl()
   ): Future[AsyncWebSocket]  =
  result = newAsyncWebsocketClient(
    # string concatenation needed here in case `path` cotnains query
    (if ssl: "wss" else: "ws") & "://" & host & ":" & $port & "/" & path,
    additionalHeaders, protocols, userAgent, sslContext)
