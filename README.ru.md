# Packet Sender Lite
Еще один сканер(граббер) баннеров сетевых сервисов.

###### Ключевые моменты:
1. Python asyncio, uvloop (python3.8)
2. Возможно задавать программно-генерируемые(Python) payloads


###### Для чего написан и почему так:
1. Код запускается на машинах с 1 vCPU и минимум памяти
2. Много сетевых соединений
3. Читает из stdin ip-адреса и ip-адреса сетей (CIDR) нотации
4. Читает из файла(приоритет - чтение из stdin)
5. Пишет в stdout результаты
6. Пишет в файл результаты(приоритет - пишет в stdout)


**_Важно_**: На вход попадают только IP-адреса или подсети в CIDR нотации.

**_Важно_**: На выходе только записи в виде json, заданной в коде структуры.

Приоритеты расставлены таким образом ввиду практики запуска кода внутри контейнеров(docker) у облачных провайдеров и использованием 
механизма конвейера (pipe)

Например при перенаправление результатов от сканирования zmap:

`zmap 192.168.1.0/24 -B 8M -q -v 1 -p 22 -P1 -i eno1 | python3.8 packetsenderlite.py --port=22 --max-size=1024 --show-statistics
`

`{"data":{"tcp":{"status":"success","result":{"response":{"content_length":41,"body_raw":"U1NILTIuMC1PcGVuU1NIXzcuNnAxIFVidW50dS00dWJ1bnR1MC4zDQo=","body_sha256":"0eff183edbf2746b458b51e6aed65665496fedc822d0c896ae59197e868aeed3","body_sha1":"bc86277c55d769e5add65794cfbb0cabba506961","body_md5":"68191084e335183f4fc51f7a18553ac2","body_hexdump":"MDAwMDAwMDA6IDUzIDUzIDQ4IDJEIDMyIDJFIDMwIDJEICA0RiA3MCA2NSA2RSA1MyA1MyA0OCA1RiAgU1NILTIuMC1PcGVuU1NIXwowMDAwMDAxMDogMzcgMkUgMzYgNzAgMzEgMjAgNTUgNjIgIDc1IDZFIDc0IDc1IDJEIDM0IDc1IDYyICA3LjZwMSBVYnVudHUtNHViCjAwMDAwMDIwOiA3NSA2RSA3NCA3NSAzMCAyRSAzMyAwRCAgMEEgICAgICAgICAgICAgICAgICAgICAgIHVudHUwLjMuLg=="}},"options":null}},"ip":"192.168.1.10","port":22}

{"data":{"tcp":{"status":"success","result":{"response":{"content_length":21,"body_raw":"U1NILTIuMC1PcGVuU1NIXzUuMg0K","body_sha256":"9ebba06d45bb9cae35e725c85b5968852e14c8d73aab1896ed05980691befa61","body_sha1":"5b80dacb14164c8c500698834786e898d733a6c5","body_md5":"abf778fec86c27ae305ea2d32adcc8c1","body_hexdump":"MDAwMDAwMDA6IDUzIDUzIDQ4IDJEIDMyIDJFIDMwIDJEICA0RiA3MCA2NSA2RSA1MyA1MyA0OCA1RiAgU1NILTIuMC1PcGVuU1NIXwowMDAwMDAxMDogMzUgMkUgMzIgMEQgMEEgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA1LjIuLg=="}},"options":null}},"ip":"192.168.1.254","port":22}

{"data":{"tcp":{"status":"success","result":{"response":{"content_length":21,"body_raw":"U1NILTIuMC1PcGVuU1NIXzcuNg0K","body_sha256":"9ae40817ea3d91386735ff9f2718b671a674451a47b3383265bda0e50723e5cd","body_sha1":"f145af4e81c7deb22ad008a00bce7b247eb309c5","body_md5":"637979461f8598b67da0a9d82e7dc68f","body_hexdump":"MDAwMDAwMDA6IDUzIDUzIDQ4IDJEIDMyIDJFIDMwIDJEICA0RiA3MCA2NSA2RSA1MyA1MyA0OCA1RiAgU1NILTIuMC1PcGVuU1NIXwowMDAwMDAxMDogMzcgMkUgMzYgMEQgMEEgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA3LjYuLg=="}},"options":null}},"ip":"192.168.1.14","port":22}

{"duration":8.257557,"valid targets":3,"success":3,"fails":0}`

###### Особенности:

**Важно**  Через настройки возможно задавать payload в байтах. То есть то, что будет отправлено в соединении. 
Payloads возможно указывать в настройках 3 способами:
1. через опцию _--single-payload_ возможно задать в base64 кодировке байты, которые будут отправлены в обнаруженный сервис
2. через опцию _--list-payloads_ возможно задать список файлов, которые будут открыты в режиме _read bytes(rb)_,
и их содержимое будет отправлено в обнаруженный сервис(**важно:** не последовательно, а в рамках разных соединений)
3. через опции _--python-payloads_ и _--generator-payloads_. Указанные опции позволяют задать название модуля(файла) 
Python, и функции в нем(либо по умолчанию: _generator_payloads_). Данная функция должна возвращать список элементов.
Каждый элемент словарь -Dict, с определенным набором полей:
`payload = {'payload' : _payload,
               'data_payload': {'payload_raw': _payload_base64,
                               'variables': []
                               }
               }`.
 Где _payload_ - bytes, а в ключе _data_payload_ содержатся данные для понимания, что было отправлено в сервис.
 Данный раздел сложно объяснить, в будущем будет упрощено, сейчас лучше сразу смотреть пример: 
 [_example_python_payloads/http_get.py_](https://github.com/JohnEskimSmith/PacketSenderLite/blob/master/example_python_payloads/http_get.py)
 
 4. Если не указать payload - то сканер работает как простой граббер баннеров. То есть он вообще ничего не отправляет в
 обнаруженый сервис. Это важно, например zgrab2 в модуле banner - отправляет всегда "\\n" [zgrab2 banner module source](https://github.com/zmap/zgrab2/blob/6eaaa2fa00331a278875e783f0d2a6aabcb06481/modules/banner/scanner.go#L21). 
В отличии от zgrab2 в настоящем проекте не предусмотрено значения по умолчанию. То есть, например, при подключении
к web сервису по 80 порту, при пустом payload соединение будет разорвано по timeout без результата, потому как http сервис "обычно"
ждет "команды". А, например, при подключении по ssh - сервис ssh - сам первый отправляет 
banner(так же как и зачастую, например, ftp сервис)

Все изменения по проекту отображаются в [**_CHANGELOG(ru)_**](https://github.com/JohnEskimSmith/PacketSenderLite/blob/master/CHANGELOG.ru.md)


 
 
               