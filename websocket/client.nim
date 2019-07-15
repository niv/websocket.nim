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

import net, asyncdispatch, asyncnet, base64, times, strutils,
  nativesockets, streams, tables, oids, uri

import httpclient except ProtocolError

when NimMinor < 18:
  import securehash
else:
  import std/sha1

import shared

import private/hex

const WebsocketUserAgent* = "websocket.nim (https://github.com/niv/websocket.nim)"

when not defined(ssl):
  type SslContext = ref object
var defaultSsl {.threadvar.}: SslContext

proc defaultSslContext: SslContext =
  result = defaultSsl
  when defined(ssl):
    if result.isNil:
      result = newContext(protTLSv1, verifyMode = CVerifyNone)
      doAssert(not result.isNil, "failure to initialize SSL context")
      defaultSsl = result



proc newAsyncWebsocketClient*(uri: Uri,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.async.} =
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
  case uri.scheme
  of "ws":
    uri.scheme = "http"
  of "wss":
    uri.scheme = "https"
  else:
    raise newException(ProtocolError,
      "uri scheme has to be 'ws' for plaintext or 'wss' for websocket over ssl.")

  var client = newAsyncHttpClient()
  client.headers = newHttpHeaders({
    "Connection": "Upgrade",
    "Upgrade": "websocket",
    "User-Agent": userAgent,
    "Cache-Control": "no-cache",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": key
  })
  if protocols.len != 0:
    client.headers["Sec-WebSocket-Protocol"] = protocols.join(", ")
  for h in additionalHeaders:
    client.headers[h[0]] = h[1]
  let resp = await client.get($uri)
  if resp.code != Http101:
    client.getSocket().close()
    raise newException(ProtocolError,
      "Server did not reply with a websocket upgrade: " & $resp.code)

  let ws = new AsyncWebSocket
  ws.kind = SocketKind.Client
  ws.sock = client.getSocket()

  result = ws

proc newAsyncWebsocketClient*(host: string, port: Port, path: string, ssl = false,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket]  =
  newAsyncWebsocketClient(parseUri(
    (if ssl: "wss" else: "ws") & "://" &
    host & ":" & $port & "/" & path
  ))

proc newAsyncWebsocketClient*(uri: string, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.async.} =
  let uriBuf = parseUri(uri)
  result = await newAsyncWebsocketClient(uriBuf, additionalHeaders, protocols, userAgent, ctx)

proc newAsyncWebsocket*(host: string, port: Port, path: string, ssl = false,
    additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.deprecated.} =
  ## **Deprecated since 0.3.0**: Use `newAsyncWebsocketClient`:idx: instead.
  result = newAsyncWebsocketClient(host, port, path, ssl, additionalHeaders, protocols, userAgent, ctx)

proc newAsyncWebsocket*(uri: Uri, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.deprecated.} =
  ## **Deprecated since 0.3.0**: Use `newAsyncWebsocketClient`:idx: instead.
  result = newAsyncWebsocketClient(uri, additionalHeaders, protocols, userAgent, ctx)

proc newAsyncWebsocket*(uri: string, additionalHeaders: seq[(string, string)] = @[],
    protocols: seq[string] = @[],
    userAgent: string = WebsocketUserAgent,
    ctx: SslContext = defaultSslContext()
   ): Future[AsyncWebSocket] {.deprecated.} =
  ## **Deprecated since 0.3.0**: Use `newAsyncWebsocketClient`:idx: instead.
  result = newAsyncWebsocketClient(uri, additionalHeaders, protocols, userAgent, ctx)