---- MODULE MC ----
EXTENDS SPA_Attack, TLC

\* CONSTANT definitions @modelParameterConstants:0ClientCfg
const_16456883249062000 == 
[LoginID |->1,Key |-> 44,SrcIp |->11]
----

\* CONSTANT definitions @modelParameterConstants:1SDPSvrCfg
const_16456883249063000 == 
[IP |-> 12,Port |-> 8000]
----

\* CONSTANT definitions @modelParameterConstants:2SvrCfg
const_16456883249064000 == 
[IP |-> 22,Port |-> 80]
----

\* CONSTANT definitions @modelParameterConstants:3MATCH_ANY
const_16456883249065000 == 
65536
----

\* CONSTANT definitions @modelParameterConstants:4USER_BASEPORT
const_16456883249066000 == 
1024
----

\* CONSTANT definitions @modelParameterConstants:5ATTACKER_BASEPORT
const_16456883249067000 == 
2024
----

\* CONSTANT definitions @modelParameterConstants:6AttackerCfg
const_16456883249068000 == 
[SrcIp |-> 11]
----

\* CONSTANT definitions @modelParameterConstants:7NAT_FLAG
const_16456883249069000 == 
TRUE
----

\* CONSTANT definitions @modelParameterConstants:8UNKNOWN_AUTH_ID
const_164568832490610000 == 
65535
----

=============================================================================
\* Modification History
\* Created Thu Feb 24 15:38:44 CST 2022 by 10227694
