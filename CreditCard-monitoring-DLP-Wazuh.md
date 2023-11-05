# Add credit card data monitoring with Wazuh for DLP
## Reglas
Para monitorear datos sensibles (Datos de tarjetas de credito) en equipos Windows/Linux
Agregar reglas en **/var/ossec/etc/rules/local_rules.xml** en el servidor Wazuh u OSSEC
```xml
<rule id="100002" level="12">
        <if_sid>516</if_sid>
        <status>high</status>
        <action>Detected</action>
        <options>alert_by_email</options>
        <description>Possible Unencrypted PANs - Primary Account Number - Credit Card VISA</description>
        <group>pci_dss_10.5.5,pci_dss_10.6.1,</group>
    </rule>

   <rule id="100003" level="12">
        <if_sid>516</if_sid>
        <status>high</status>
        <action>Detected</action>
        <options>alert_by_email</options>
        <description>Possible Unencrypted PANs - Primary Account Number - Credit Card MasterCard</description>
        <group>pci_dss_10.5.5,pci_dss_10.6.1,</group>
    </rule>
   <rule id="100004" level="12">
        <if_sid>516</if_sid>
        <status>high</status>
        <action>Detected</action>
        <options>alert_by_email</options>
        <description>Possible Unencrypted PANs - Primary Account Number - Credit Card AMEX</description>
        <group>pci_dss_10.5.5,pci_dss_10.6.1,</group>
    </rule>
   <rule id="100005" level="12">
        <if_sid>516</if_sid>
        <status>high</status>
        <action>Detected</action>
        <options>alert_by_email</options>
        <description>Possible Unencrypted PANs - Primary Account Number - Credit Card Diners Club</description>
        <group>pci_dss_10.5.5,pci_dss_10.6.1,</group>
    </rule>

   <rule id="100006" level="12">
        <if_sid>516</if_sid>
        <status>high</status>
        <action>Detected</action>
        <options>alert_by_email</options>
        <description>Possible Unencrypted PANs - Primary Account Number - Credit Card Discover</description>
        <group>pci_dss_10.5.5,pci_dss_10.6.1,</group>
    </rule>
    <rule id="100007" level="12">
        <if_sid>516</if_sid>
        <status>high</status>
        <action>Detected</action>
        <options>alert_by_email</options>
        <description>Possible Unencrypted PANs - Primary Account Number - Credit Card JCB</description>
        <group>pci_dss_10.5.5,pci_dss_10.6.1,</group>
    </rule>
```

## Expresiones regulares
Al momento de guardar los cambios en este archivo **/var/ossec/etc/shared/default/win_audit_rcl.txt** en el servidor, el cambio se refleja en todos los agentes y se reinicia el servicio automaticamente para aplicar los cambios.

> **NOTA1:** Pasa algo raro de que se detiene el servicio de OssecSVC en los agentes.
> Supongo que es por el feature de Anti-flooding mechanism.
> Esto sucede cuando los archivos a escanear o revisar son demasiados.
> Por eso lo acote poniendo los tipos de archivos especificos que queria monitorear en la expresion regular.

Con esto definimos que carpeta queremos escanear en los agentes

Agregar en **/var/ossec/etc/shared/default/win_audit_rcl.txt**
```bash
$home_dir=C:\Users;
```

De aqui me base para poder construir las regex:
Primero este [post](https://www.immutablesecurity.com/index.php/2010/01/13/detecting-sensitive-info-with-ossec/)
Donde exponen como configurar para detectar SSN. Que por lo que veo esta roto el link XD.

Luego para poder construir las regex para tarjetas de credito, primero se intento con las regex que andan por ahi en internet,
pero no funcionan porque segun entendi en la documentacion de Wazuh, se trata de hacer que se lean regex de la forma mas simple posible para hacer el proceso mas rapido.
Bueno primero fui a la [documentacion de Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html), que habla con respecto a la parte de regex.

Supongo que alguien mas experimentado si le entiende, pero yo no logre formar las regex con esa info, asi que me fui al [origen](https://github.com/ossec/ossec-hids/tree/master/src/os_regex)
Ahi observe lo siguiente:

```
Each regular expression can be followed by:

    +  ->  To match one or more times (eg \w+ or \d+)
    *  ->  To match zero or more times (eg \w* or \p*)"
```

Ademas de que hay una carpeta con ejemplos XD

El punto es que de algo como esto:
```regex
Mastercard - ^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$
```

Que encontre [aqui](https://www.regular-expressions.info/creditcard.html)
Se tuvo que pasar a esto

```regex
Mastercard - 51\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|52\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|53\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|54\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|55\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|222\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|223\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|224\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|225\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|226\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|227\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|228\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|229\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|23\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|24\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|25\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|26\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|270\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|271\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|2720\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d
```

Y asi cada tipo de tarjeta

Y ya eso me dio la pauta para construir poco a poco las regex.
Ya! Mucho choro, aqui les dejo las regex, por si a alguien le sirve.

> **NOTA:**
> Con la regex de Mastercard hay un detalle, que aún no sé porque sucede, pero pues ya le di workaround XD 
> En ese regex de Mastercard hay 20 diferentes regex concatenadas con el pipe "|"
> Sucede que si pones toda la cadena, te va a mandar un error en el archivo de logs que dice:

```bash
rootcheck: DEBUG: Checking entry: 'Possible Unencrypted PANs - Primary Account Number - Credit Card MasterCard'.
rootcheck: ERROR: (1252): Invalid rk configuration value: 'd'.
ossec-agent: DEBUG: Agent buffer empty.
```

Si pones 19 regex, funciona, pero si pongo la 20, cualquiera que sea, marca ese error.
Al final lo que hice fue partirla a la mitad, 10 regex en una entrada y 10 en otra. Por eso hay dos checks de tipo Mastercard

Esto se agrega al final de **/var/ossec/etc/shared/default/win_audit_rcl.txt**
```bash
# Detect possible PANs
[Possible Unencrypted PANs - Primary Account Number - Credit Card VISA] [any] []
d:$home_dir -> r:txt$|log$|json$|xml$|pdf$|doc$|docx$|xls$|xlsx$|ppt$|pptx$ -> r:4\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d;

[Possible Unencrypted PANs - Primary Account Number - Credit Card MasterCard] [any] []
d:$home_dir -> r:txt$|log$|json$|xml$|pdf$|doc$|docx$|xls$|xlsx$|ppt$|pptx$ -> r:51\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|52\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|53\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|54\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|55\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|222\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|223\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|224\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|225\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d;

[Possible Unencrypted PANs - Primary Account Number - Credit Card MasterCard] [any] []
d:$home_dir -> r:txt$|log$|json$|xml$|pdf$|doc$|docx$|xls$|xlsx$|ppt$|pptx$ -> r:226\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|227\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|228\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|229\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|23\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|24\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|25\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|26\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|270\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|271\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|2720\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d;

[Possible Unencrypted PANs - Primary Account Number - Credit Card AMEX] [any] []
d:$home_dir -> r:txt$|log$|json$|xml$|pdf$|doc$|docx$|xls$|xlsx$|ppt$|pptx$ -> r:34\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d|37\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d;

[Possible Unencrypted PANs - Primary Account Number - Credit Card Diners Club] [any] []
d:$home_dir -> r:txt$|log$|json$|xml$|pdf$|doc$|docx$|xls$|xlsx$|ppt$|pptx$ -> r:300\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d|301\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d|302\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d|303\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d|304\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d|305\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d|36\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d|38\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d;

[Possible Unencrypted PANs - Primary Account Number - Credit Card Discover] [any] []
d:$home_dir -> r:txt$|log$|json$|xml$|pdf$|doc$|docx$|xls$|xlsx$|ppt$|pptx$ -> r:6011\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d|65\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d;

[Possible Unencrypted PANs - Primary Account Number - Credit Card JCB] [any] []
d:$home_dir -> r:txt$|log$|json$|xml$|pdf$|doc$|docx$|xls$|xlsx$|ppt$|pptx$ -> r:2131\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d|1800\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d|35\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d\p*\s*\d\d\d\d;
```
