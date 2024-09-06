# flutter TSA (Time Stamping Authority)  client rfc3161

a PoC of timestamping content with Flutter thanks to Digicert's timestamp server

(SHA-256 as hash method)

tested on macos and android configurations

will fails with web configuration because digicert does not provide CORS header


Example

```
 try {
      TSARequest tsq = TSARequest.fromFile(filepath: file.path);
      Response r = await tsq.run(hostname: "http://timestamp.digicert.com");   
 } on Exception catch (e) {
      setState(() {
        _iStatusCode = 0;
        _errorMessage = "exception : ${e.toString()}";
      });
 }
```
