# Flutter TSA (Time Stamping Authority)  client rfc3161

tested on macos and android configurations (will fails with flutter web if TSA host does not provide CORS header)


```
import 'package:dio/dio.dart';
import 'TSARequest.dart';

// ...


 try {
      TSARequest tsq = TSARequest.fromFile(filepath: file.path);
      Response r = await tsq.run(hostname: "http://timestamp.digicert.com");   
 } on Exception catch (e) { 
     debugPrint(e.toString());
 }
```
