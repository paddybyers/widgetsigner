widgetsigner
============

A java utility for signing w3c widgets

```
usage: WidgetSigner -w <widget> -k <keystore> -p <password> -a <alias> -s
                    <signtype> [-i <intermediatekeystore>] [-c] [-d
                    <identifier>] [-IMEI <imei1>,<imei2>,... ] [-MEID
                    <MEID1>,<MEID2>,...] [-r <crl>]
 -a,--alias <arg>                  PrivateKey and Certificate's alias in
                                   end keystore
 -c,--created                      add dsp:Created SignatureProperty
 -d,--identifier <arg>             format string for dsp:Identifier
                                   SignatureProperty
 -i,--intermediatekeystore <arg>   Path of (.jks/.bks) keystore containing
                                   intermediate certificates (not password
                                   protected)
 -IMEI <arg>                       IMEI strings
 -k,--keystore <arg>               Path of PKCS12 keystore used to be sign
                                   the widget
 -MEID <arg>                       MEID strings
 -p,--passwd <arg>                 password of end keystore
 -r,--crl <arg>                    Path of CRL to embed in signature
 -s,--signtype <arg>               0--author signature, 1--distributor
                                   signature 1, 2--distributor signature
                                   2, ...
 -w,--widget <arg>                 Path of widget to be signed
```
