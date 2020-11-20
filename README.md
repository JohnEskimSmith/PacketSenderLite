# Packet Sender Lite
Packet Sender Lite is an utility to allow sending TCP, SSL (encrypted TCP) packets and receiving responses.
It can be used for both commercial and personal use.

*Read this in other languages: [English](README.md), [Ru](README.ru.md).*

### Examples:

#### Search all DNS servers 

```
zmap 95.165.0.0/16 -B 10M -q -v 1 -p 53 -P1 | python3.8 packetsenderlite.py --port=53 --single-payload='AB4ABgEAAAEAAAAAAAAHdmVyc2lvbgRiaW5kAAAQAAM='
```

```json
{"duration":12.76594,"valid targets":464,"success":452,"fails":12}
```

###### result (one of the successful):

```json
{
  "data": {
    "tcp": {
      "status": "success",
      "result": {
        "response": {
          "request": {},
          "content_length": 58,
          "body_raw": "ADgABoUAAAEAAQAAAAAHdmVyc2lvbgRiaW5kAAAQAAPADAAQAAMAAAAAAA4NTm90IERpc2Nsb3NlZA==",
          "body_sha256": "9780cca22de1cef8ac091fddb090728798ed79839733a9dd861b8364d47149d9",
          "body_sha1": "1c36d688485df2c8335fc16a5e173c2551704c50",
          "body_md5": "d6a2daaa972ea8aa1e9d017276c42b64",
          "body_hexdump": "MDAwMDAwMDA6IDAwIDM4IDAwIDA2IDg1IDAwIDAwIDAxICAwMCAwMSAwMCAwMCAwMCAwMCAwNyA3NiAgLjguLi4uLi4uLi4uLi4udgowMDAwMDAxMDogNjUgNzIgNzMgNjkgNkYgNkUgMDQgNjIgIDY5IDZFIDY0IDAwIDAwIDEwIDAwIDAzICBlcnNpb24uYmluZC4uLi4uCjAwMDAwMDIwOiBDMCAwQyAwMCAxMCAwMCAwMyAwMCAwMCAgMDAgMDAgMDAgMEUgMEQgNEUgNkYgNzQgIC4uLi4uLi4uLi4uLi5Ob3QKMDAwMDAwMzA6IDIwIDQ0IDY5IDczIDYzIDZDIDZGIDczICA2NSA2NCAgICAgICAgICAgICAgICAgICAgIERpc2Nsb3NlZA=="
        }
      },
      "options": {
        "data_payload": {
          "payload_raw": "AB4ABgEAAAEAAAAAAAAHdmVyc2lvbgRiaW5kAAAQAAM=",
          "variables": []
        }
      }
    }
  },
  "ip": "95.165.96.213",
  "port": 53
}
```

#### Search all DNS servers and filter *Microsoft DNS*

option _--single-contain='TWljcm9zb2Z0IEROUw=='_ means the following: 'TWljcm9zb2Z0IEROUw==' == 'Microsoft DNS'. Filtering results by the content of the substring in the string, only and all in bytes representation in BASE64.

```
zmap 95.165.0.0/16 -B 10M -q -v 1 -p 53 -P1 | python3.8 packetsenderlite.py --port=53 --single-payload='AB4ABgEAAAEAAAAAAAAHdmVyc2lvbgRiaW5kAAAQAAM=' --single-contain='TWljcm9zb2Z0IEROUw=='
```

```json
{"duration":12.679582,"valid targets":464,"success":4,"fails":6}
```
###### result (one of the successful):

```json
{
  "data": {
    "tcp": {
      "status": "success",
      "result": {
        "response": {
          "request": {},
          "content_length": 78,
          "body_raw": "AEwABoUAAAEAAQAAAAAHdmVyc2lvbgRiaW5kAAAQAAPADAAQAAFYAgAAACIhTWljcm9zb2Z0IEROUyA2LjEuNzYwMSAoMURCMTVGNzUp",
          "body_sha256": "9135c657341e444b27f13a6bdd79e64d81aadaf2dfcdc5a0b52c3acd6aba23ce",
          "body_sha1": "c3a54bb960c1dc6e1c490d45658744dee9f71f7d",
          "body_md5": "4b8fb8ecaa9163c7892bacfdee563183",
          "body_hexdump": "MDAwMDAwMDA6IDAwIDRDIDAwIDA2IDg1IDAwIDAwIDAxICAwMCAwMSAwMCAwMCAwMCAwMCAwNyA3NiAgLkwuLi4uLi4uLi4uLi4udgowMDAwMDAxMDogNjUgNzIgNzMgNjkgNkYgNkUgMDQgNjIgIDY5IDZFIDY0IDAwIDAwIDEwIDAwIDAzICBlcnNpb24uYmluZC4uLi4uCjAwMDAwMDIwOiBDMCAwQyAwMCAxMCAwMCAwMSA1OCAwMiAgMDAgMDAgMDAgMjIgMjEgNEQgNjkgNjMgIC4uLi4uLlguLi4uIiFNaWMKMDAwMDAwMzA6IDcyIDZGIDczIDZGIDY2IDc0IDIwIDQ0ICA0RSA1MyAyMCAzNiAyRSAzMSAyRSAzNyAgcm9zb2Z0IEROUyA2LjEuNwowMDAwMDA0MDogMzYgMzAgMzEgMjAgMjggMzEgNDQgNDIgIDMxIDM1IDQ2IDM3IDM1IDI5ICAgICAgICA2MDEgKDFEQjE1Rjc1KQ=="
        }
      },
      "options": {
        "data_payload": {
          "payload_raw": "AB4ABgEAAAEAAAAAAAAHdmVyc2lvbgRiaW5kAAAQAAM=",
          "variables": []
        }
      }
    }
  },
  "ip": "95.165.155.221",
  "port": 53
}
```

#### HTTP GET

Here custom payload generator function is used to generate HTTP 1.1 GET payload for each target host: 

`python3.8 packetsenderlite.py -f targets.txt --port=80 --python-payloads="/home/user/PacketSenderLite/example_python_payloads/http_get.py" --generator-payloads="generator_http_get"`

`python3.8 packetsenderlite.py -f targets.txt  --port=80 --python-payloads="example_python_payloads.http_get" --generator-payloads="generator_http_get"`

`zmap 95.165.0.0/16 -B 10M -q -v 1 -p 80 -P1 | python3.8 packetsenderlite.py --port=80 --python-payloads="example_python_payloads.http_get" --generator-payloads="generator_http_get"`