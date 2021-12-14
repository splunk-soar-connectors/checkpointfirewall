[comment]: # "Auto-generated SOAR connector documentation"
# Check Point Firewall

Publisher: Splunk  
Connector Version: 2\.1\.2  
Product Vendor: Check Point Software Technologies  
Product Name: Check Point Firewall  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app supports a variety of endpoint and network based containment actions on Check Point Firewall

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Check Point Firewall asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Management Server URL with port \(e\.g\. https\://10\.10\.10\.10\:443\)
**verify\_server\_cert** |  required  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password
**domain** |  optional  | string | Domain

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[list policies](#action-list-policies) - List policies  
[list layers](#action-list-layers) - List access layers  
[block ip](#action-block-ip) - Block an IP/subnet  
[unblock ip](#action-unblock-ip) - Unblock an IP/subnet   
[list hosts](#action-list-hosts) - List hosts  
[add host](#action-add-host) - Add host   
[delete host](#action-delete-host) - Delete host  
[logout session](#action-logout-session) - Logout of an exisiting session  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

This action logs into the device using a REST API call to check the connection and credentials configured\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list policies'
List policies

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.to | numeric | 
action\_result\.data\.\*\.from | numeric | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.packages\.\*\.uid | string | 
action\_result\.data\.\*\.packages\.\*\.name | string |  `check point policy` 
action\_result\.data\.\*\.packages\.\*\.type | string | 
action\_result\.data\.\*\.packages\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.packages\.\*\.domain\.name | string | 
action\_result\.data\.\*\.packages\.\*\.domain\.domain\-type | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list layers'
List access layers

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.to | numeric | 
action\_result\.data\.\*\.from | numeric | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.access\-layers\.\*\.uid | string | 
action\_result\.data\.\*\.access\-layers\.\*\.name | string |  `check point layer` 
action\_result\.data\.\*\.access\-layers\.\*\.type | string | 
action\_result\.data\.\*\.access\-layers\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.access\-layers\.\*\.domain\.name | string | 
action\_result\.data\.\*\.access\-layers\.\*\.domain\.domain\-type | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block ip'
Block an IP/subnet

Type: **contain**  
Read only: **False**

The <b>ip</b> parameter supports the following formats\:<ul><li>Simple IP\: For example 123\.123\.123\.123</li><li>IP, Subnet mask\: 123\.123\.0\.0 255\.255\.0\.0</li><li>CIDR Notation\: 123\.123\.0\.0/16</li></ul>This action takes multiple steps to block an IP/subnet\:<ul><li>Log in to the REST endpoint on Check Point to get a session ID\.</li><li>Check for an existing network object for the supplied IP/subnet\.</li><li>Add the network object if it does not already exist\.</li><li>Check for a rule associated with the network object if it already exists\.</li><li>Create a rule at the top of the policy that drops all traffic going to the supplied IP/subnet\.</li><li>Publish the session\.</li><li>Push the changes to the policy's configured firewalls\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to block | string |  `ip` 
**policy** |  required  | Policy | string |  `check point policy` 
**layer** |  required  | Layer | string |  `check point layer` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.uid | string | 
action\_result\.data\.\*\.vpn\.\*\.uid | string | 
action\_result\.data\.\*\.vpn\.\*\.name | string | 
action\_result\.data\.\*\.vpn\.\*\.type | string | 
action\_result\.data\.\*\.vpn\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.vpn\.\*\.domain\.name | string | 
action\_result\.data\.\*\.vpn\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.data\.\*\.uid | string | 
action\_result\.data\.\*\.data\.\*\.name | string | 
action\_result\.data\.\*\.data\.\*\.type | string | 
action\_result\.data\.\*\.data\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.data\.\*\.domain\.name | string | 
action\_result\.data\.\*\.data\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.time\.\*\.uid | string | 
action\_result\.data\.\*\.time\.\*\.name | string | 
action\_result\.data\.\*\.time\.\*\.type | string | 
action\_result\.data\.\*\.time\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.time\.\*\.domain\.name | string | 
action\_result\.data\.\*\.time\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.track\.uid | string | 
action\_result\.data\.\*\.track\.name | string | 
action\_result\.data\.\*\.track\.type | string | 
action\_result\.data\.\*\.track\.domain\.uid | string | 
action\_result\.data\.\*\.track\.domain\.name | string | 
action\_result\.data\.\*\.track\.domain\.domain\-type | string | 
action\_result\.data\.\*\.action\.uid | string | 
action\_result\.data\.\*\.action\.name | string | 
action\_result\.data\.\*\.action\.type | string | 
action\_result\.data\.\*\.action\.domain\.uid | string | 
action\_result\.data\.\*\.action\.domain\.name | string | 
action\_result\.data\.\*\.action\.domain\.domain\-type | string | 
action\_result\.data\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.domain\.name | string | 
action\_result\.data\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.source\.\*\.uid | string | 
action\_result\.data\.\*\.source\.\*\.name | string | 
action\_result\.data\.\*\.source\.\*\.type | string | 
action\_result\.data\.\*\.source\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.source\.\*\.domain\.name | string | 
action\_result\.data\.\*\.source\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.enabled | boolean | 
action\_result\.data\.\*\.service\.\*\.uid | string | 
action\_result\.data\.\*\.service\.\*\.name | string | 
action\_result\.data\.\*\.service\.\*\.type | string | 
action\_result\.data\.\*\.service\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.service\.\*\.domain\.name | string | 
action\_result\.data\.\*\.service\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.meta\-info\.lock | string | 
action\_result\.data\.\*\.meta\-info\.creator | string | 
action\_result\.data\.\*\.meta\-info\.creation\-time\.posix | numeric | 
action\_result\.data\.\*\.meta\-info\.creation\-time\.iso\-8601 | string | 
action\_result\.data\.\*\.meta\-info\.last\-modifier | string | 
action\_result\.data\.\*\.meta\-info\.last\-modify\-time\.posix | numeric | 
action\_result\.data\.\*\.meta\-info\.last\-modify\-time\.iso\-8601 | string | 
action\_result\.data\.\*\.meta\-info\.validation\-state | string | 
action\_result\.data\.\*\.install\-on\.\*\.uid | string | 
action\_result\.data\.\*\.install\-on\.\*\.name | string | 
action\_result\.data\.\*\.install\-on\.\*\.type | string | 
action\_result\.data\.\*\.install\-on\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.install\-on\.\*\.domain\.name | string | 
action\_result\.data\.\*\.install\-on\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.data\-negate | boolean | 
action\_result\.data\.\*\.destination\.\*\.uid | string | 
action\_result\.data\.\*\.destination\.\*\.name | string | 
action\_result\.data\.\*\.destination\.\*\.type | string | 
action\_result\.data\.\*\.destination\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.destination\.\*\.domain\.name | string | 
action\_result\.data\.\*\.destination\.\*\.domain\.domain\-type | string | 
action\_result\.data\.\*\.track\-alert | string | 
action\_result\.data\.\*\.custom\-fields\.field\-1 | string | 
action\_result\.data\.\*\.custom\-fields\.field\-2 | string | 
action\_result\.data\.\*\.custom\-fields\.field\-3 | string | 
action\_result\.data\.\*\.source\-negate | boolean | 
action\_result\.data\.\*\.data\-direction | string | 
action\_result\.data\.\*\.service\-negate | boolean | 
action\_result\.data\.\*\.action\-settings\.enable\-identity\-captive\-portal | boolean | 
action\_result\.data\.\*\.destination\-negate | boolean | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.layer | string |  `check point layer` 
action\_result\.parameter\.policy | string |  `check point policy` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock ip'
Unblock an IP/subnet 

Type: **correct**  
Read only: **False**

The <b>ip</b> parameter supports the following formats\:<ul><li>Simple IP\: For example 123\.123\.123\.123</li><li>IP, Subnet mask\: 123\.123\.0\.0 255\.255\.0\.0</li><li>CIDR Notation\: 123\.123\.0\.0/16</li></ul>This action takes multiple steps to unblock an IP/subnet\:<ul><li>Log in to the REST endpoint on Check Point to get a session ID\.</li><li>Check for an existing network object for the supplied IP/subnet\.</li><li>Check for a rule associated with the network object if it exists\.</li><li>Delete the rule if it exists\.</li><li>Publish the session\.</li><li>Push the changes to the policy's configured firewalls\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to unblock | string |  `ip` 
**policy** |  required  | Policy | string |  `check point policy` 
**layer** |  required  | Layer | string |  `check point layer` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.message | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.layer | string |  `check point layer` 
action\_result\.parameter\.policy | string |  `check point policy` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list hosts'
List hosts

Type: **correct**  
Read only: **False**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.to | numeric | 
action\_result\.data\.\*\.from | numeric | 
action\_result\.data\.\*\.total | numeric | 
action\_result\.data\.\*\.objects\.\*\.uid | string | 
action\_result\.data\.\*\.objects\.\*\.name | string | 
action\_result\.data\.\*\.objects\.\*\.type | string | 
action\_result\.data\.\*\.objects\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.objects\.\*\.domain\.name | string | 
action\_result\.data\.\*\.objects\.\*\.domain\.domain\-type | string |  `domain` 
action\_result\.data\.\*\.objects\.\*\.ipv4\-address | string |  `ip` 
action\_result\.data\.\*\.objects\.\*\.ipv6\-address | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add host'
Add host 

Type: **correct**  
Read only: **False**

The <b>ip</b> parameter supports the following formats\:<ul><li>IPv4\: For example 123\.123\.123\.123</li><li>IPv6\: For example 2001\:0db8\:0000\:0000\:0000\:ff00\:0042\:7879</li></ul>This action will always prioritize using the <b>ip</b> parameter unless <b>ipv4</b> and/or <b>ipv6</b> parameters are specified\. If both ipv4 and ipv6 addresses are required, use the corresponding parameters explicitly\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Object/host name \(must be unique in the domain\) | string | 
**ip** |  optional  | IPv4 or IPv6 address to add \(if both addresses are required use ipv4 and ipv6 fields explicitly\) | string |  `ip`  `ipv6` 
**ipv4** |  optional  | IPv4 address to add | string |  `ip` 
**ipv6** |  optional  | IPv6 address to add | string |  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.uid | string | 
action\_result\.data\.\*\.icon | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.color | string | 
action\_result\.data\.\*\.domain\.uid | string | 
action\_result\.data\.\*\.domain\.name | string | 
action\_result\.data\.\*\.domain\.domain\-type | string |  `domain` 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.meta\-info\.lock | string | 
action\_result\.data\.\*\.meta\-info\.creator | string | 
action\_result\.data\.\*\.meta\-info\.creation\-time\.posix | numeric | 
action\_result\.data\.\*\.meta\-info\.creation\-time\.iso\-8601 | string | 
action\_result\.data\.\*\.meta\-info\.last\-modifier | string | 
action\_result\.data\.\*\.meta\-info\.last\-modify\-time\.posix | numeric | 
action\_result\.data\.\*\.meta\-info\.last\-modify\-time\.iso\-8601 | string | 
action\_result\.data\.\*\.meta\-info\.validation\-state | string | 
action\_result\.data\.\*\.read\-only | numeric | 
action\_result\.data\.\*\.ipv6\-address | string |  `ipv6` 
action\_result\.data\.\*\.nat\-settings\.auto\-rule | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.ipv6 | string |  `ipv6` 
action\_result\.parameter\.name | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.ipv4\-address | string |  `ip` 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.ipv4 | string |  `ip`   

## action: 'delete host'
Delete host

Type: **correct**  
Read only: **False**

To delete a host, either specify <b>uid</b> or <b>name</b>\. If provided both, this action will prioritize the <b>uid</b> parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**uid** |  optional  | Host's unique indentifier | string | 
**name** |  optional  | Object/host name \(must be unique in the domain\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.message | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.uid | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.parameter\.name | string |   

## action: 'logout session'
Logout of an exisiting session

Type: **correct**  
Read only: **False**

This action logs out of an existing session\. For all other actions, logging out occurs automatically\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session\_id** |  required  | Session id to log out from | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.session\_id | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 