--------------------------- MODULE SPA_Attack_New ---------------------------

(***************************************************************************)
(* `^                                                                      *)
(*                                                                         *)
(* This is the specification for the improved SDP architecture and         *)
(*   algorithm which fixed the flaws related to service hidden feature.    *)                                                                 
(*  The defect study is aimed on the following materials:                  *)
(*                                                                         *)
(* https://cloudsecurityalliance.org/artifacts/software-defined-           *)
(*           perimeter-zero-trust-specification-v2/                        *)                                           
(* http://www.cipherdyne.org/fwknop/                                       *)
(*                                                                         *)
(* ^'  Author: Dong.luming@zte.com.cn                                      *)
(***************************************************************************)

EXTENDS FiniteSets, Sequences, Naturals, Integers, TLC, Bitwise, Functions

\* The end point user's (SDP client) configuration, includes local IP and account Info. 
CONSTANT ClientCfg (*@type: [LoginID |-> String, Key |-> Integer, SrcIp |-> Integer ];*)

\* The SDP controller's exposure service info, inludes listening IP and  port.
CONSTANT SDPSvrCfg (*@type: [IP |-> Integer, Port |-> Integer];*)

\* The target server's exposure service info, inludes server IP and listening port.
CONSTANT SvrCfg  (*@type: [IP |-> Integer, Port |-> Integer];*)

\* The attacker's configuration, inludes local IP.
CONSTANT AttackerCfg (*@type: [SrcIp |-> Integer ];*)

\* The match any type value for a ACL Rule.
CONSTANT MATCH_ANY (*@type: Integer;*)

\*For an user's socket link , the start of random local port range.
CONSTANT USER_BASEPORT(*@type: Integer;*)

\*For an attacker's socket link , the start of random local port range.
CONSTANT ATTACKER_BASEPORT(*@type: Integer;*)

\*If the attacker and user are in the same LAN with a shared public IP for NAT.
CONSTANT NAT_FLAG(*@type: BOOL;*)

\*According to SDP protocol,each Single Packet Authorization (SPA) session has a unique Auth_ID field,  
\*and each SPA session on control plane is served for a related data access request on data plane.
\*So, for a data access link originated from the legistimate user, there must exists a corresponding SPA session in history. 
\*Therefore, for each data acess link info, we use AuthID field to specify which SPA session it relates.
\*But there always be exceptions, if a fake data access link is originated from the attacker, its homing SPA session may not certain.       
\*So,we specificly define a invalid Auth_ID value.If a data access link with an invalid authentication session ID, 
CONSTANT UNKNOWN_AUTH_ID(*@type: Integer;*)

\*If the legistimate user and attacker are in the same LAN with shared public IP, then the local port range after SNAT must not conflict with each other.
ASSUME  (NAT_FLAG = TRUE => AttackerCfg.SrcIp = ClientCfg.SrcIp /\ USER_BASEPORT # ATTACKER_BASEPORT) 

ASSUME (SDPSvrCfg.IP # ClientCfg.SrcIp /\ SDPSvrCfg.IP # AttackerCfg.SrcIp)

ASSUME (SvrCfg.IP # ClientCfg.SrcIp /\ SvrCfg.IP # AttackerCfg.SrcIp) 

ASSUME (SvrCfg.IP # SDPSvrCfg.IP) 

(***************************************************************************)
(* `^ \centering                                                           *)
(* The variables related to legistimate user's state machine                             *)
(* ^'                                                                      *)
(***************************************************************************)
\* The legistimate user's status indicates which session it is undergoing now.
VARIABLE uState(*@type: {"Start_Auth","Auth_End","Auth_End_Connecting","Connected"};*) 

\* The legistimate user's IP address get from configuration.
VARIABLE uIP(*@type: Integer;*)

\* The legistimate user's ID for authentication.
VARIABLE uID(*@type: String;*)

\* The legistimate user's Secret Key for authentication.
VARIABLE Key(*@type: Integer;*)

\* The legistimate user's Sync counter value (Time Stamp) for SDP authentication, the counter increases randomly each auth session to prevent from Replay attack.
VARIABLE uTstamp(*@type: Integer;*)

\* The legistimate user's knowledge for target server's info get from input configuration data.
VARIABLE uSDPSvrInfo(*@type: [IP |-> Integer, Port |-> Integer];*)

\* The legistimate user's knowledge for target server's info got from configuration.
VARIABLE uSvrInfo(*@type: [IP |-> Integer, Port |-> Integer];*)

\* The legistimate user's TCP links connected with target server for data plane access.
VARIABLE uTCPLinkSet (*@type: Set( [sIP      |-> Integer,
                                    sPort    |-> Integer,
                                    dIP      |-> Integer,
                                    dPort    |-> Integer,
                                    State    |-> {"SYN_SENT","ESTABLISHED"},
                                    Retrans  |-> {TRUE,FALSE} ]);
                      *)

\* The legistimate user's Authenticaiton sessions in history recorded in Log.Each session identified by a SPA message. 
VARIABLE uAuthSession (*@type: Set(  [MsgID   |-> "SPA_AUTH", 
                                      sIP     |-> uIP, 
                                      sPort   |-> SelLocalPort(uTstamp,USER_BASEPORT),  
                                      dIP     |-> uSDPSvrInfo.IP,    \*The SDP Controller's IP and port for SPA protocol 
                                      dPort   |-> uSDPSvrInfo.Port, 
                                      ClientID|-> uID, 
                                      Tstamp |-> uTstamp,    \*increased each session to anti Replay
                                      CliIP   |-> Encrypt(uIP,Key), \* <CliIP,CliPort,SvrIP,SvrPort> is the connecting TCP link info to the target server 
                                      CliPort |-> Encrypt(SelLocalPort(uTstamp,USER_BASEPORT)+1,Key),  \*the random local port of TCP connection for data access  
                                      SvrIP   |-> Encrypt(uSvrInfo.IP,Key),  \* Target Server's exposure service Info, need to kept secret
                                      SvrPort |-> Encrypt(uSvrInfo.Port,Key),  
                                      HMAC    |-> CalcHMAC(uIP,uID,uTstamp,Encrypt(uSvrInfo.IP,Key),Encrypt(uSvrInfo.Port,Key),Key) , \*HMAC of payload
                                      Type    |-> Set("User","Attacker")]);  \* Flag to indicate this message is built by legistimate user or attacker                                                                                                                                         
                                           \* this flag not invloved in inter-operation between SDP protocol entities,only for statistic
                      *)                                                     

\* The legistimate user equipment's packets channnel for recieving data plane packets, corresponds to its physical NIC.
VARIABLE uChannel (*@type: Sequence of TCP Packets Seq([sIP      |-> p.dIP,   \*TCP packets for data access,for this model,we 
                                                        sPort    |-> p.dPort, \*simulate the data plane access stream only by TCP connection proceudre
                                                        dIP      |-> p.sIP,   \*IE. if user establish a TCP connection with target server, that     
                                                        dPort    |-> p.sPort, \*means a sucessful data access session.
                                                        Flg      |-> Set("TCP_SYN","TCP_SYN_ACK","TCP_ACK"), \* TCP handshake packets type. 
                                                        Type     |-> Set("User","Attacker")]; \* Flag to indicate this access is initiated by legistimate user or attacker
                                                                       \* this flag not invloved in inter-operation between SDP protocol entities,only for statistic
                   *) 
\* The legistimate User's private variables ( uChannel is public variable of user, for other entity can operate and modify uChannel variable directly ) 
user_vars == <<uState, uIP, uID, Key, uTstamp, uSDPSvrInfo, uSvrInfo, uTCPLinkSet, uAuthSession>>

(***************************************************************************)
(* `^ \centering                                                           *)
(* The variables related to SDP Server's (SDP Controller) state machine    *)
(* ^'                                                                      *)
(***************************************************************************)
\* The SDP controller's status indicates this entity's service is available or not.
VARIABLE SDPSvrState(*@type: Set("Work")*)  

\* The SDP controller successfully processed Auth sessions in history recorded in Log.
VARIABLE SDPSucSession (*@type: uAuthSession*)

\* The legistimate user accounts info recorded in SDP controller's IAM system.
VARIABLE Account (*@type:  Set([ClientID |->ClientCfg.LoginID, 
                                Key      |->ClientCfg.Key])*)

\* The SDP controller's exposure SPA service info .
VARIABLE SDPSvrInfo (*@type: [IP |-> SDPSvrCfg.IP, Port |-> SDPSvrCfg.Port]*) 

\* The number of replay attack messages inspected by SDP controller 
VARIABLE ReplayCount (*@type: Integer;*)

\* The number of spoof attack messages inspected by SDP controller
VARIABLE SpoofCount (*@type: Integer;*) 

\* The replay attack Auth sessions inspected by SDP controller in history recorded in Log.
VARIABLE ReplaySession (*@type: uAuthSession;*)

\* The spoof attack Auth sessions inspected by SDP controller in history recorded in Log.
VARIABLE SpoofSession (*@type: uAuthSession;*)

\* SDP controller's packets channnel for recieving control plane Auth messages, corresponds to its physical NIC.
VARIABLE AuthChannel (*@type: Sequence of SPA Auth Packets Seq( [MsgID   |-> "SPA_AUTH", 
                                      sIP     |-> uIP, 
                                      sPort   |-> SelLocalPort(uTstamp,USER_BASEPORT),  
                                      dIP     |-> uSDPSvrInfo.IP,    \*The SDP Controller's IP and port for SPA protocol 
                                      dPort   |-> uSDPSvrInfo.Port, 
                                      ClientID|-> uID, 
                                      Tstamp |-> uTstamp,    \*increased each session to anti Replay
                                      CliIP   |-> Encrypt(uIP,Key), \* <CliIP,CliPort,SvrIP,SvrPort> is the connecting TCP link info to the target server 
                                      CliPort |-> Encrypt(SelLocalPort(uTstamp,USER_BASEPORT)+1,Key),  \*the random local port of TCP connection for data access  
                                      SvrIP   |-> Encrypt(uSvrInfo.IP,Key),  \* Target Server's exposure service Info, need to kept secret
                                      SvrPort |-> Encrypt(uSvrInfo.Port,Key),  
                                      HMAC    |-> CalcHMAC(uIP,uID,uTstamp,Encrypt(uSvrInfo.IP,Key),Encrypt(uSvrInfo.Port,Key),Key) , \*HMAC of payload
                                      Type    |-> Set("User","Attacker")]);  \* Flag to indicate this message is built by legistimate user or attacker                                                                                                                                         
                                                      \* this flag not invloved in inter-operation between SDP protocol entities,only for statistic;                                                                      
                     *) 
\* The SDP controller's private variables ( AuthChannel is public variable of SDP controller, for other entity can operate and modify AuthChannel variable directly ) 
sdpsvr_vars == <<SDPSvrState, SDPSucSession, Account, SDPSvrInfo ,ReplayCount, SpoofCount, ReplaySession, SpoofSession>>

(***************************************************************************)
(* `^ \centering                                                           *)
(* The variables related to FireWall's state machine                       *)
(* ^'                                                                      *)
(***************************************************************************)
\* The FireWall's status indicates this entity's service is available or not.
\* The FireWall works in deny mode by default.
VARIABLE FwState(*@type: Set("Work")*)

\* Current Acl Rule Set maintained by the FireWall for data plane traffic. 
VARIABLE AclRuleSet(*@type: Set([sIP      |->Integer,
                                 sPort    |->Integer, \* the value can be MATCH_ANY, 
                                 dIP      |->Integer,
                                 dPort    |->Integer, 
                                 protocol |-> "TCP", 
                                 action   |-> "Accept"])*) 

\* The aged Acl Rules in history recorded in FireWall's log. 
VARIABLE AgedRuleSet(*@type: Set([sIP      |->Integer,
                                 sPort    |->Integer, \* the value can be MATCH_ANY, 
                                 dIP      |->Integer,
                                 dPort    |->Integer, 
                                 protocol |-> "TCP", 
                                 action   |-> "Accept"])*) 

\* The dropped packets by FireWall in history recorded in log. 
VARIABLE DropPackets(*@type: Set([sIP      |-> p.dIP,   \* Only data plane TCP packets are processed by FireWall 
                                  sPort    |-> p.dPort, 
                                  dIP      |-> p.sIP,       
                                  dPort    |-> p.sPort, 
                                  Flg      |-> Set("TCP_SYN","TCP_SYN_ACK","TCP_ACK"), \* TCP handshake packets type. 
                                  Type     |-> Set("User","Attacker")];)*)

\* FireWall's control plane channnel for receiving Openflow instruction from SDP controller to configure data access Acl Rule, corresponds to one of its physical NIC.                                  
VARIABLE FwCtlChannel (*@type: Sequence of Acl config instructions Seq([Rule |-> AclRule, op |-> Set("Add","Del")])
                      *) 

\* FireWall's ingress data plane channnel for receiving packets from end point entities , corresponds to one of its physical NIC.
VARIABLE FwDataChannel (*@type: Sequence of Data Packets Seq([sIP      |-> p.dIP,   \* Only data plane TCP packets are processed by FireWall 
                                     sPort    |-> p.dPort, 
                                     dIP      |-> p.sIP,       
                                     dPort    |-> p.sPort, 
                                     Flg      |-> Set("TCP_SYN","TCP_SYN_ACK","TCP_ACK"), \* TCP handshake packets type. 
                                     Type     |-> Set("User","Attacker")];)*)
 
\* The FireWall's private variables ( FwDataChannel and FwCtlChannel are public variable of FW, for other entity can operate and modify them directly ) 
fw_vars == <<FwState, AclRuleSet, AgedRuleSet ,DropPackets>>

(***************************************************************************)
(* `^ \centering                                                           *)
(* The variables related to Attacker's state machine                       *)
(* ^'                                                                      *)
(***************************************************************************)
\* The Attacker's status indicates this entity's is spying or not.
VARIABLE aState(*@type: Set("Listen")*)

\* The Attacker's current knowledge about legistimate user's auth action learned by sniffing legistimate user's auth message.
VARIABLE AuthKnowledge(*@type: uAuthSession*)

\* The Attacker initiated SPA attack sesssions in history recorded in log. Each session is identified by a fake SPA message.
VARIABLE aSession (*@type: uAuthSession*)

\* The Attacker initiated TCP connections towards the target server. Each link corresponds to an service probe attack to the target server.
VARIABLE aTCPLinkSet(*@type:Set( [sIP      |-> Integer,
                                  sPort    |-> Integer,
                                  dIP      |-> Integer,
                                  dPort    |-> Integer,
                                  State    |-> {"SYN_SENT","ESTABLISHED"}
                                  AuthID   |-> Integer] \* The AuthID is used for relating to a captured auth message
                                )  \* For this model, once the attacker spy a SPA message, it will undertake a data attack to the target server.
                              \* The value UNKNOWN_AUTH_ID indicates the attack is not originate from a captured auth message, but a captured data message   
                    *)              
\* The number of sucessfully sniffed SPA messages by attacker.
VARIABLE sniffCount (*@type: Integer;*) 

\* All the successfully sniffed SPA messages by attacker in history recorded in log.
VARIABLE CapAuthMsg (*@type: uAuthSession;*)

\* Attacker maintained increasing sequence number to build local port field for TCP links of different service probe attack.
VARIABLE aCounter(*@type: Integer;*)  

\* Attacker's IP address, which is got by configuration.
\* If NAT_FLAG = TRUE, then attacker and legistimate user located in the same LAN and share same public IP (aIP = uIP).
VARIABLE aIP(*@type: Integer;*)

\* The Attacker's current knowledge about legistimate user's data access learned by sniffing legistimate user's TCP handshake packets with target server.
VARIABLE DataKnowledge(*@type: Set( [sIP      |-> p.dIP,   \* Only data plane TCP packets are processed by FireWall 
                                     sPort    |-> p.dPort, 
                                     dIP      |-> p.sIP,       
                                     dPort    |-> p.sPort, 
                                     Flg      |-> Set("TCP_SYN","TCP_SYN_ACK","TCP_ACK"), \* TCP handshake packets type. 
                                     Type     |-> Set("User","Attacker")])
                       *)
\* All the successfully sniffed user data packets by attacker in history recorded in log. 
VARIABLE CapDataMsg(*@type: DataKnowledge*)

\* The attacker's packets channnel for recieving data plane packets, corresponds to its physical NIC.
VARIABLE aChannel(*@type: uChannel*)  

\* The attacker's private variables ( aChannel is public variable of attacker, for other entity can operate and modify aChannel variable directly ) 
attacker_vars == <<aState, AuthKnowledge,  aSession, aTCPLinkSet, sniffCount, CapAuthMsg, aCounter, aIP, DataKnowledge, CapDataMsg>>

(***************************************************************************)
(* `^ \centering                                                           *)
(* The variables related to target service server's state machine          *)
(* ^'                                                                      *)
(***************************************************************************)
\* The target server's status indicates this entity's service is available or not.
VARIABLE sState(*@type: Set("Listen")*)

\* The TCP socket maintained in server side initiated from end points towards target server.
VARIABLE sTCPLinkSet(*@type: Set( [sIP      |-> p.dIP,   \* Only data plane TCP packets are processed by FireWall 
                                   sPort    |-> p.dPort, 
                                   dIP      |-> p.sIP,       
                                   dPort    |-> p.sPort, 
                                   Flg      |-> Set("TCP_SYN","TCP_SYN_ACK","TCP_ACK"), \* TCP handshake packets type. 
                                   Type     |-> Set("User","Attacker")])
                       *)

\* The target server's exposed service info got from configuration.
VARIABLE sSvrInfo(*@type: [IP |-> SvrCfg.IP, Port |-> SvrCfg.Port]*)

\* The server's packets channnel for recieving data plane packets from endpoint equipments, corresponds to its physical NIC.
VARIABLE sChannel(*@type: uChannel*)  

\* The target server's private variables ( sChannel is public variable of server, for other entity can operate and modify sChannel variable directly ) 
server_vars == <<sState, sTCPLinkSet, sSvrInfo>>

(***************************************************************************)
(* `^ \centering                                                           *)
(* All the public variables of the model                                   *)
(* ^'                                                                      *)
(***************************************************************************)

Public_vars == <<uChannel,AuthChannel,FwCtlChannel,FwDataChannel,aChannel,sChannel>>

(***************************************************************************)
(* `^ \centering                                                           *)
(* All the variables that consititute the global state machine             *)
(* ^'                                                                      *)
(***************************************************************************)
vars == <<user_vars,sdpsvr_vars,fw_vars,attacker_vars,server_vars,Public_vars>> 


(***************************************************************************)
(* `^                                                                      *)
(*  Common functions and operators                                         *)
(* ^'                                                                      *)
(***************************************************************************)
\* Sequence S to Set
Seq2Set(S) == Range(S) 

\*Select local port when client create socket connection, 
\*the parameter count is related to  new session's timestamp, and will increase for each new link session.
SelLocalPort(count,base) == (CHOOSE x \in (count + base)..(100 + base) :TRUE) 

\*Simulate Symmetric-key based cryptographic algorithm AES-256: 
\*For encrypt function, the operator is simplified by a single XOR operation,
\*only to ensure that Decrypt(Encrypt(d,k), k) = d while Decrypt(Encrypt(d,k), k') gives a meaningless result when k' # k.
\*For the attack mode in this Spec is based on Delov-Yao Intruder Model, so we just focus on the vulnerabilities of
\*SDP framework design and never challenge the cryptographic algorithm like AES and HMAC that it relies on. 
Encrypt(d, k) == d ^^ k
\*simulate Symmetric-key algorithm AES-256: Decrypt function     
DeCrypt(d,k) == Encrypt(d, k) 
    
\*simulate Hash-based message authentication code (HMAC) algorithm used for SPA message authorization. 
CalcHMAC(n1,n2,n3,n4,n5,n6,n7,key) == Encrypt(n1+n2+n3+n4+n5+n6+n7, key)

(***************************************************************************)
(* `^                                                                      *)
(*  Init state description of legistimate user                                   *)
(* ^'                                                                      *)
(***************************************************************************)
\* User Init: Load input configuration data and ready to launch an access to target server
\* the init state is ready to start a auth session. 
UsrInit == /\ uState = "Start_Auth"
           /\ uID =  ClientCfg.LoginID
           /\ Key = ClientCfg.Key
           /\ uIP = ClientCfg.SrcIp  
           /\ uTstamp = 0
           /\ uSDPSvrInfo = [IP |-> SDPSvrCfg.IP, Port |-> SDPSvrCfg.Port]
           /\ uSvrInfo = [IP |-> SvrCfg.IP, Port |-> SvrCfg.Port]
           /\ uTCPLinkSet = {} 
           /\ uChannel = <<>>
           /\ uAuthSession = {}

(***************************************************************************)
(* `^                                                                      *)
(*  Next state actions of legistimate user                                       *)
(* ^'                                                                      *)
(***************************************************************************)

UsrBuildTcpSynPkt ==
    [sIP      |-> uIP,
     sPort    |-> SelLocalPort(uTstamp,USER_BASEPORT)+1, \* the new data access corresponds to the latest auth session by local port field.
     dIP      |-> uSvrInfo.IP,
     dPort    |-> uSvrInfo.Port, 
     Flg      |-> "TCP_SYN", 
     Type     |-> "User"]  
     
\* Action 1: UsrConnectServerEnhance
\* legistimate user perform enhanced SPA auth which is triggered by and syncronized with the data plane TCP connecting event to target server.
\* Variables changed: <uState,uAuthSession,uTstamp,AuthChannel,uTCPLinkSet,FwDataChannel>
UsrConnectServerEnhance ==
    /\ uState = "Start_Auth"
    /\ uState' = "Auth_End_Connecting"      
    /\ uTstamp' = uTstamp+1  \* uTstamp increases each session for anti-replay.
    /\ AuthChannel' = Append(AuthChannel,  
                             [MsgID   |-> "SPA_AUTH", 
                              sIP     |-> uIP, 
                              sPort   |-> SelLocalPort(uTstamp,USER_BASEPORT), \* the random port of SPA message 
                              dIP     |-> uSDPSvrInfo.IP, 
                              dPort   |-> uSDPSvrInfo.Port, 
                              ClientID|-> uID, 
                              Tstamp |-> uTstamp,
                              CliIP   |-> Encrypt(uIP,Key), \* <CliIP,CliPort,SvrIP,SvrPort> is the connecting TCP link info to the target server 
                              CliPort |-> Encrypt(SelLocalPort(uTstamp,USER_BASEPORT)+1,Key),  \*the random local port of TCP connection for data access    
                              SvrIP   |-> Encrypt(uSvrInfo.IP,Key), 
                              SvrPort |-> Encrypt(uSvrInfo.Port,Key),  
                              HMAC    |-> CalcHMAC(uIP,uID,uTstamp,Encrypt(uIP,Key),Encrypt(SelLocalPort(uTstamp+1,USER_BASEPORT),Key),
                                                   Encrypt(uSvrInfo.IP,Key),Encrypt(uSvrInfo.Port,Key),Key) ,
                              Type    |->"User"]
                            )
    /\ uAuthSession' = uAuthSession \cup {Head(AuthChannel')} \* Auth session is recorded in Log
    /\ uTCPLinkSet = {}
    /\ uTCPLinkSet' = {   \*We assume the user only launch one data access session. 
        [sIP      |-> UsrBuildTcpSynPkt.sIP,
         sPort    |-> UsrBuildTcpSynPkt.sPort,
         dIP      |-> UsrBuildTcpSynPkt.dIP,
         dPort    |-> UsrBuildTcpSynPkt.dPort,
         State    |-> "SYN_SENT",    \* Create new TCP socket corresponds to the latest Auth session, TCP link state is "SYN_SENT" 
         Retrans  |-> FALSE
        ]             } 
    /\ FwDataChannel' = Append(FwDataChannel, UsrBuildTcpSynPkt) \* Send TCP SYN packet to FireWall. 
    /\ UNCHANGED <<uIP, uID, Key,uSDPSvrInfo, uSvrInfo>>
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED fw_vars
    /\ UNCHANGED attacker_vars
    /\ UNCHANGED server_vars 
    /\ UNCHANGED <<uChannel,FwCtlChannel,aChannel,sChannel>>   

\* Action 2: UsrRcvSynAck
\* legistimate user receive TCP SYN Ack packet from target server which 
\* indicates data TCP link establised. This represents the user has
\* successfully fufilled a data access. 
\* Variables changed: <uState, uTCPLinkSet, uChannel,FwDataChannel>

HasMatchLink(p,LinkSet) ==
  \E x \in LinkSet:  /\ p.sIP = x.dIP         
                     /\ p.sPort = x.dPort
                     /\ p.dIP = x.sIP
                     /\ p.dPort = x.sPort
                     
GetMatchLink(p,LinkSet) ==  \*get match TCB (TCP control Block) for a received TCP packet
    CHOOSE x \in LinkSet: /\ p.sIP = x.dIP         
                          /\ p.sPort = x.dPort
                          /\ p.dIP = x.sIP
                          /\ p.dPort = x.sPort  


EndPointBuildTcpAckPkt(p,t) == \* End point equipments might be a legistimate user or attacker
    [sIP      |-> p.dIP,
     sPort    |-> p.dPort,
     dIP      |-> p.sIP,
     dPort    |-> p.sPort, 
     Flg      |-> "TCP_ACK", 
     Type     |-> t] 

UsrRcvSynAck ==
    /\ ( \/ uState = "Auth_End_Connecting"
         \/ uState = "Auth_End_Reconnecting"
       )
    /\ uTCPLinkSet # {}
    /\ uChannel # <<>>
    /\ Head(uChannel).Flg  = "TCP_SYN_ACK"
    /\ Head(uChannel).Type = "User"
    /\ HasMatchLink(Head(uChannel),uTCPLinkSet) \* Receive TCP_SYN_ACK from target server and match the connecting TCP socket 
    /\ LET l == GetMatchLink(Head(uChannel),uTCPLinkSet)
       IN  uTCPLinkSet' = (uTCPLinkSet \ {l}) 
                      \cup { [sIP      |-> l.sIP,
                              sPort    |-> l.sPort,
                              dIP      |-> l.dIP,
                              dPort    |-> l.dPort,
                              State    |-> "ESTABLISHED", \* Updata TCP link status to established
                              Retrans  |-> l.Retrans 
                             ]   
                            }
    /\ uState' = "Connected" \* The user successfully access the target server
    /\ uChannel' = Tail(uChannel) \*Send TCP ACK packet (the last step of hand shake)  to target server
    /\ FwDataChannel' = Append(FwDataChannel, EndPointBuildTcpAckPkt(Head(uChannel),"User"))
    /\ UNCHANGED <<uIP, uID, Key, uTstamp, uSDPSvrInfo, uSvrInfo, uAuthSession>>
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED fw_vars
    /\ UNCHANGED attacker_vars
    /\ UNCHANGED server_vars 
    /\ UNCHANGED <<AuthChannel,FwCtlChannel,aChannel,sChannel>> 
 

\* Action 3: UsrReConnectServer
\* If TCP SYN pakcets sent from legistimate user to target server dropped by the FireWall due to
\* the corresponding ACL Rule not configed yet, then legistimate user as TCP client will re-send SYN packet
\* to simulate the re-transmission mechanism of TCP protocol .
\* To simplify the model, we just trigger the retransmisson action only after the related ACL Rule is configed.
\* Variables changed: <FwDataChannel,uState,uTCPLinkSet> 

 \*Whether there exists 4 Tuple ACL Rule in AclSet that exactly match the given TCP link l 
TcpLnkHasMatchAcl(l,AclSet) == \E r \in AclSet: 
        /\ r.sIP  = l.sIP 
        /\ r.sPort = l.sPort
        /\ r.dIP  = l.dIP
        /\ r.dPort  = l.dPort
        /\ r.action = "Accept"                  

\* Whether the fire wall has packets dropping record for the given TCP link x.
WithDropPkts(x) == \E p \in DropPackets: 
        /\ p.sIP = x.sIP 
        /\ p.sPort = x.sPort
        /\ p.dIP = x.dIP
        /\ p.dPort = x.dPort   

SYN_Timeout_Lnk == CHOOSE x \in uTCPLinkSet:(x.State = "SYN_SENT" /\ WithDropPkts(x)) 

UsrReConnectServer ==
    /\ uState = "Auth_End_Connecting"
    /\ uState' = "Auth_End_Reconnecting"  
    /\ uTCPLinkSet # {}
    /\ \E x \in uTCPLinkSet:( x.State = "SYN_SENT" /\ WithDropPkts(x))
    /\ TcpLnkHasMatchAcl(SYN_Timeout_Lnk,AclRuleSet) 
    /\ FwDataChannel' = Append(FwDataChannel, 
         [sIP      |-> SYN_Timeout_Lnk.sIP,
          sPort    |-> SYN_Timeout_Lnk.sPort, 
          dIP      |-> SYN_Timeout_Lnk.dIP,
          dPort    |-> SYN_Timeout_Lnk.dPort, 
          Flg      |-> "TCP_SYN", 
          Type     |-> "User"]  ) \* Resend TCP SYN packet to FireWall. 
    /\ uTCPLinkSet' = (uTCPLinkSet \ {SYN_Timeout_Lnk}) 
                      \cup { [sIP      |-> SYN_Timeout_Lnk.sIP,
                              sPort    |-> SYN_Timeout_Lnk.sPort,
                              dIP      |-> SYN_Timeout_Lnk.dIP,
                              dPort    |-> SYN_Timeout_Lnk.dPort,
                              State    |-> SYN_Timeout_Lnk.State, 
                              Retrans  |-> TRUE  \*to record the retansmission event ever happened in link setup process
                             ]   
                            }
    /\ UNCHANGED <<uIP, uID, Key, uTstamp, uSDPSvrInfo, uSvrInfo, uAuthSession>>
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED fw_vars
    /\ UNCHANGED attacker_vars
    /\ UNCHANGED server_vars 
    /\ UNCHANGED <<uChannel,AuthChannel,FwCtlChannel,aChannel,sChannel>>      

(***************************************************************************)
(* `^                                                                      *)
(*  Init state description of SDP Controller                               *)
(* ^'                                                                      *)
(***************************************************************************)           
\* SDP Controller Init: Load configuration and ready to provide SPA auth service.           
SDPSvrInit == /\ SDPSvrState = "Work"
              /\ SDPSucSession = {}  
              /\ Account = {[ClientID |->ClientCfg.LoginID, Key  |->ClientCfg.Key]} \*Load user account config into IAM
              /\ SDPSvrInfo =  [IP |-> SDPSvrCfg.IP, Port |-> SDPSvrCfg.Port] \* Service IP and port for SPA protocol   
              /\ AuthChannel = <<>>  
              /\ ReplayCount = 0
              /\ SpoofCount = 0 
              /\ ReplaySession = {}
              /\ SpoofSession = {} 
              
(***************************************************************************)
(* `^                                                                      *)
(*  Next state actions of SDP Controller                                   *)
(* ^'                                                                      *)
(***************************************************************************)  
\* Action 3: SDPSvrProcSpaAuthEx
\* SDP Controller process received improved version SPA message.
\* Scenario 3: Request from legistimate user, controller then instruct firewall to admit data access after authenticaiton.
\* Scenario 1 2: controller recognize spoof and replay attack.   
\* Variables changed: <AuthChannel,SDPSucSession,ReplaySession,SpoofSession,ReplayCount, SpoofCount,FwCtlChannel>


\* if a coming SPA message SN match the history message recorded in anti-replay window
\* then it must be recognized as a replay attack packet.  
FindAntiReplay(msg,wnd) == \E r \in wnd : (msg.ClientID = r.ClientID /\ msg.Tstamp = r.Tstamp)
                                                                 
\*For a recognized replay attack message, SDP controller drop it and recorded in the log. 
SDPSvrAntiReplayAtk == 
    /\ AuthChannel' = Tail(AuthChannel) \*Drop packet
    /\ ReplayCount' = ReplayCount+ 1  \* Increase statistics
    /\ ReplaySession' = ReplaySession \cup {Head(AuthChannel)} \*Update log 

\*For a recognized spoof attack message, SDP controller drop it and recorded in the log.                     
SDPSvrAntiSpoof == 
    /\ AuthChannel' = Tail(AuthChannel) \*Drop packet
    /\ SpoofCount' = SpoofCount + 1 \* Increase statistics
    /\ SpoofSession' = SpoofSession \cup {Head(AuthChannel)} \*Update log  
                   

\* SDP controller implement authenticaiton triggered by a received SPA message
\* The authentication is implemented by recaculate the HMAC according the user account Info
SpaProcAuth(msg,accounts) == 
    \E a \in accounts : ( /\ a.ClientID = msg.ClientID  \* user ID must match
       \*Recaclulate the HMAC value by using local stored user Key and then compare the value of corresponding field in SPA packet.
                          /\ CalcHMAC(msg.sIP,msg.ClientID,msg.Tstamp,msg.CliIP,msg.CliPort,msg.SvrIP,msg.SvrPort,a.Key) = msg.HMAC 
                        )    
\* Get the correspond key by user ID from IAM stored accounts                      
GetKey(id,accounts) == (CHOOSE a \in accounts : a.ClientID = id).Key   

\* SDP controller instruct FireWall to config Acl Rule by sending instruction message to FireWall's control plane channel 
SDPSvrCfgFw(Acl,op) == 
    /\ FwCtlChannel' = Append(FwCtlChannel,[Rule |-> Acl, op |-> op])


SDPSvrProcSpaAuthEx == 
    /\ SDPSvrState = "Work"
    /\ AuthChannel # <<>>
    /\ Head(AuthChannel).MsgID = "SPA_AUTH" \*check the packet is SPA message
    /\ Head(AuthChannel).dIP = SDPSvrInfo.IP
    /\ Head(AuthChannel).dPort = SDPSvrInfo.Port
    /\ IF FindAntiReplay(Head(AuthChannel),SDPSucSession) = TRUE \* case 1: the packet is a replay message 
       THEN 
         /\ SDPSvrAntiReplayAtk \*drop packets and record exception into log
         /\ UNCHANGED user_vars
         /\ UNCHANGED <<SDPSvrState, SDPSucSession, Account, SDPSvrInfo, SpoofCount, SpoofSession>>
         /\ UNCHANGED fw_vars 
         /\ UNCHANGED attacker_vars
         /\ UNCHANGED server_vars
         /\ UNCHANGED <<uChannel,FwCtlChannel,FwDataChannel,aChannel,sChannel>>
       ELSE
         /\ IF SpaProcAuth(Head(AuthChannel),Account) = FALSE  \* case 2: it is a spoof message or from unknown user
            THEN 
              /\ SDPSvrAntiSpoof \*drop packets and record exception into log
              /\ UNCHANGED user_vars
              /\ UNCHANGED <<SDPSvrState, SDPSucSession, Account, SDPSvrInfo, ReplayCount, ReplaySession>>
              /\ UNCHANGED fw_vars
              /\ UNCHANGED attacker_vars
              /\ UNCHANGED server_vars
              /\ UNCHANGED <<uChannel,FwCtlChannel,FwDataChannel,aChannel,sChannel>>                             
            ELSE  \*case 3: Authenticated successfully, then send instruction to FW to allow data access towards target server.
              /\ SDPSvrCfgFw([sIP      |-> DeCrypt(Head(AuthChannel).CliIP,GetKey(Head(AuthChannel).ClientID,Account)), 
                              sPort    |-> DeCrypt(Head(AuthChannel).CliPort,GetKey(Head(AuthChannel).ClientID,Account)),  \*For the improved version this Acl Rule is 4 tuple, for data access source port is determined now.
                              dIP      |-> DeCrypt(Head(AuthChannel).SvrIP,GetKey(Head(AuthChannel).ClientID,Account)),
                              dPort    |-> DeCrypt(Head(AuthChannel).SvrPort,GetKey(Head(AuthChannel).ClientID,Account)), 
                              protocol |-> "TCP", 
                              action   |-> "Accept"],
                              "Add"  \* The instruction code is to Add a new rule.
                             )
              /\ SDPSucSession' = SDPSucSession \cup {Head(AuthChannel)} \*record in log
              /\ AuthChannel' = Tail(AuthChannel)
              /\ UNCHANGED user_vars
              /\ UNCHANGED <<SDPSvrState, Account, SDPSvrInfo ,ReplayCount, SpoofCount, ReplaySession, SpoofSession>> 
              /\ UNCHANGED fw_vars
              /\ UNCHANGED attacker_vars
              /\ UNCHANGED server_vars
              /\ UNCHANGED <<uChannel,FwDataChannel,aChannel,sChannel>>            
              

(***************************************************************************)
(* `^                                                                      *)
(*  Init state description of FireWall                                     *)
(* ^'                                                                      *)
(***************************************************************************)               
\* Fire wall init: power on and enter work state, by default, it works in deny mode and will drop
\* any ingress data packets.          
FwInit ==  /\ FwCtlChannel = <<>>
           /\ FwDataChannel = <<>>
           /\ FwState = "Work"
           /\ AclRuleSet = {}
           /\ AgedRuleSet = {} 
           /\ DropPackets = {} 

(***************************************************************************)
(* `^                                                                      *)
(*  Next state actions of FireWall                                         *)
(* ^'                                                                      *)
(***************************************************************************)
\* Action 4: FwProcAclCfg
\* FireWall receive Acl Rule config instruction from control plane channel, and hence create a 3 Tuple rule for data access 
\* Variables changed: <FwCtlChannel, AclRuleSet>
FwProcAclCfg ==
    /\ FwState = "Work"
    /\ FwCtlChannel # <<>>
    /\ Head(FwCtlChannel).op = "Add" \*Check instruction message format
    /\ AclRuleSet' = AclRuleSet \cup {Head(FwCtlChannel).Rule} \* Update local maintained rule table   
    /\ FwCtlChannel' = Tail(FwCtlChannel)
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED attacker_vars
    /\ UNCHANGED server_vars
    /\ UNCHANGED <<FwState,AgedRuleSet, DropPackets>>
    /\ UNCHANGED <<uChannel,AuthChannel,FwDataChannel,aChannel,sChannel>>

    
\* Action 5: FwProcEndPointAccessEx
\* FireWall receive a ingress data packet from end point side and implement filtering function according to configed 4 Tuple Acl Rule.
\* For the improved version, the Firewall only confied with 4 tuples ACL Rules and ACL Rule automatically create function is prohibited .
\* Variables changed: <sChannel, AclRuleSet,FwDataChannel,DropPackets >
                        
\*Whether the TCP packet match a given 4 tuple rule.
AclMatch4Tuple(p,Acl) == \E r \in Acl: 
              /\ p.sIP = r.sIP  \* (sIP,sPort,dIP,dPort) must match exactly
              /\ p.dIP = r.dIP 
              /\ r.sPort # MATCH_ANY 
              /\ r.sPort = p.sPort 
              /\ p.dPort = r.dPort
              /\ r.action = "Accept"
    
FwProcEndPointAccessEx  ==
   /\ FwState = "Work"
   /\ FwDataChannel # <<>>
   /\ ( \/ Head(FwDataChannel).Flg  = "TCP_SYN"  \* to simplify the model, we only consider TCP connection proceudre for data access
        \/ Head(FwDataChannel).Flg  = "TCP_ACK" \* the end point euipments as TCP client, only send TCP_SYN and TCP_ACK packet to target server.
      )
   /\ (IF AclMatch4Tuple(Head(FwDataChannel),AclRuleSet) 
       THEN   \*CASE1 : the incoming packets exactly match a 4 tuple rule
         /\ sChannel' = Append(sChannel, Head(FwDataChannel)) \* route the packets to target server
         /\ FwDataChannel' = Tail(FwDataChannel)
         /\ AclRuleSet' = AclRuleSet     
         /\ DropPackets' = DropPackets 
       ELSE   \*CASE2 : the incoming packetsnot match any 4 tuple rule
         /\ FwDataChannel' = Tail(FwDataChannel) 
         /\ AclRuleSet' = AclRuleSet
         /\ sChannel' = sChannel   \*just drop the packets
         /\ DropPackets' = DropPackets \cup {Head(FwDataChannel)} \* record it into exception log 
      ) 
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED attacker_vars
    /\ UNCHANGED <<FwState,AgedRuleSet>>
    /\ UNCHANGED server_vars    
    /\ UNCHANGED <<uChannel,AuthChannel,FwCtlChannel,aChannel>>               

(***************************************************************************)
(* `^                                                                      *)
(*  Init state description of target service server                        *)
(* ^'                                                                      *)
(***************************************************************************) 
\* Target TCP server init and begin listening on its service IP and Port.                
ServerInit == /\ sState = "Listen"
              /\ sSvrInfo = [IP |-> SvrCfg.IP, Port |-> SvrCfg.Port] \*Load configuration
              /\ sTCPLinkSet = {}
              /\ sChannel = <<>>
          
(***************************************************************************)
(* `^                                                                      *)
(*  Next state actions of target service server                            *)
(* ^'                                                                      *)
(***************************************************************************) 
\* Action 6: ServerRcvTCPSyn
\* Target server recieve a TCP SYN packet from client side and try to allocate a new TCB.
\* Because the Firewall dose not filter server to endpoint direction packets, so to simplify the model, the server direcly sent TCP ACK packets to
\* uChannel.
\* Variables changed: <sTCPLinkSet,sChannel,uChannel,aChannel >

\*Whether the coming packet indicates a new connection
NewLink(p,LinkSet) ==
     \A x \in LinkSet: \*without matching TCB (TCP Control Block)
       \/ x.sIP # p.sIP
       \/ x.dIP # p.dIP
       \/ x.sPort # p.sPort
       \/ x.dPort # p.dPort       
       
ServerRcvTCPSyn ==
    /\ sState = "Listen"
    /\ sChannel # <<>>
    /\ Head(sChannel).Flg  = "TCP_SYN"
    /\ Head(sChannel).dIP = sSvrInfo.IP \* check incoming packets format
    /\ Head(sChannel).dPort = sSvrInfo.Port
    /\ sChannel' = Tail(sChannel)
    /\( IF NewLink(Head(sChannel),sTCPLinkSet) 
        THEN \*CASE1 : New TCP SYN packets
         /\ sTCPLinkSet' = sTCPLinkSet \cup { \*create a TCB and update local link set.
             [dIP      |-> Head(sChannel).sIP,
              dPort    |-> Head(sChannel).sPort,
              sIP      |-> Head(sChannel).dIP,
              sPort    |-> Head(sChannel).dPort,
              Type     |-> Head(sChannel).Type,
              State    |-> "SYN_RCVD"   \* the TCB 's state is SYN_RCVD
             ] }
         /\ ( IF Head(sChannel).Type = "User" 
               THEN \*If the client is legistimate user, then send TCP_SYN_ACK packet to legistimate user.
                ( /\ uChannel' = Append(uChannel, [
                                   sIP      |-> Head(sChannel).dIP,
                                   sPort    |-> Head(sChannel).dPort,
                                   dIP      |-> Head(sChannel).sIP,
                                   dPort    |-> Head(sChannel).sPort, 
                                   Flg      |-> "TCP_SYN_ACK", 
                                   Type     |-> Head(sChannel).Type]                                    
                                  )
                  /\ aChannel' = aChannel
                )  
               ELSE  \*If the client is attacker, then send TCP_SYN_ACK packet to attacker.
                ( /\ aChannel' = Append(aChannel, [
                                   sIP      |-> Head(sChannel).dIP,
                                   sPort    |-> Head(sChannel).dPort,
                                   dIP      |-> Head(sChannel).sIP,
                                   dPort    |-> Head(sChannel).sPort, 
                                   Flg      |-> "TCP_SYN_ACK", 
                                   Type     |-> Head(sChannel).Type]                                    
                                  )
                  /\ uChannel' = uChannel
                )                    
             ) 
       ELSE \*CASE2 : duplicated TCP SYN packet,just neglect it for we don't focus on TCP SYN Flood attack.
         /\ sTCPLinkSet' = sTCPLinkSet
         /\ aChannel' = aChannel
         /\ uChannel' = uChannel
      )     
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars 
    /\ UNCHANGED attacker_vars
    /\ UNCHANGED <<sState,sSvrInfo>>
    /\ UNCHANGED fw_vars
    /\ UNCHANGED <<AuthChannel,FwCtlChannel,FwDataChannel>> 

\* Action 7: ServerRcvTcpAck
\* Target server recieve a TCP ACK packet that acknowledge the last SYN_ACK, then establish the TCP link with the client.
\* Variables changed: <sTCPLinkSet,sChannel>
ServerRcvTcpAck ==
    /\ sState = "Listen"
    /\ sChannel # <<>>
    /\ Head(sChannel).Flg  = "TCP_ACK" \* check incoming packets format
    /\ HasMatchLink(Head(sChannel),sTCPLinkSet)
    /\ GetMatchLink(Head(sChannel),sTCPLinkSet).State = "SYN_RCVD"  \* the matched TCB state must be SYN_RCVD 
    /\ sChannel' = Tail(sChannel)
    /\ LET l == GetMatchLink(Head(sChannel),sTCPLinkSet)
       IN  sTCPLinkSet' = (sTCPLinkSet \ {l}) 
                      \cup { [sIP      |-> l.sIP,
                              sPort    |-> l.sPort,
                              dIP      |-> l.dIP,
                              dPort    |-> l.dPort,
                              Type     |-> l.Type,
                              State    |-> "ESTABLISHED"  \*Update TCP link state to ESTABLISHED. 
                             ]                            \*This indicates the client has successfully accessed target server.
                            }
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars 
    /\ UNCHANGED attacker_vars
    /\ UNCHANGED <<sState,sSvrInfo>>
    /\ UNCHANGED fw_vars
    /\ UNCHANGED <<uChannel,AuthChannel,FwCtlChannel,FwDataChannel,aChannel>> 

(***************************************************************************)
(* `^                                                                      *)
(*  Init state description of Attacker                                     *)
(* ^'                                                                      *)
(***************************************************************************) 
\* Attacker init and capable of sniffing the packets on the local network.
AttackerInit == /\ aState = "Listen"
                /\ AuthKnowledge = {}
                /\ aSession = {}
                /\ aTCPLinkSet = {}
                /\ aChannel = <<>> 
                /\ sniffCount = 0
                /\ CapAuthMsg = {}
                /\ aCounter = 0
                /\ aIP = AttackerCfg.SrcIp
                /\ DataKnowledge = {}
                /\ CapDataMsg = {}
          
(***************************************************************************)
(* `^                                                                      *)
(*  Next state actions of attacker                                         *)
(* ^'                                                                      *)
(***************************************************************************) 
\* Action 8: AttackerSniffAuthChannel
\* Attacker eavesdropping SPA message from legistimate user to SDP controller by sniffing the Auth channel.
\* Once a new SPA message is captured,attacker will duplicate it into its current Auth-knowledge set.
\* We don't guarantee every new SPA message can be captured by attacker, it only has the opportuity to get each message.
\* Variables changed: <AuthKnowledge,CapAuthMsg,sniffCount>
    

\*Slect a new (which means unknown to attacker till now) SPA message from the Auth channel
\* to simulate a successful sniff. 
SelectNewAuthMsg(MsgQ,known) ==
    IF known # {}
    THEN  \*for a dedicate user, the difference among SPA messages is the value of SN (counter) field.
    CHOOSE S \in SUBSET Seq2Set(MsgQ) : (\A x \in S: (\A y \in known: x.Tstamp # y.Tstamp ))
    ELSE
    Seq2Set(MsgQ)  

\*For the attacker can also insert fake  messages into channel, but
\*for both data and auth channel, attacker only wants to capture messages from legistimate user.
\*so the PureChannel() function is to select the set of user's messages.     
PureChannel(S) == SelectSeq(S, LAMBDA x : x.Type = "User")  

AttackerSniffAuthChannel ==
    /\ aState = "Listen"
    /\ PureChannel(AuthChannel) # <<>> \*pre-condition: there exists attacker unknown legistimate user originated SPA messages on the wire.
    /\ LET l == PureChannel(AuthChannel)
       IN  /\ \E i \in 1..Len(l) : (\A x \in CapAuthMsg : l[i].Tstamp # x.Tstamp )
           /\ AuthKnowledge' = AuthKnowledge \cup  \*post-condition: attacker learned new intelligence by a successful sniffing.
                               SelectNewAuthMsg(l,CapAuthMsg)
           /\ CapAuthMsg' = CapAuthMsg \cup   \* All the captured message in history recorded in Log.
                               SelectNewAuthMsg(l,CapAuthMsg) 
    /\ sniffCount' = sniffCount + 1 \* increase statistics
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED fw_vars
    /\ UNCHANGED server_vars
    /\ UNCHANGED <<aState, aSession, aTCPLinkSet, aCounter, aIP,DataKnowledge, CapDataMsg>>   
    /\ UNCHANGED Public_vars

\* Action 9: AttackerSniffDataChannel
\* Attacker eavesdropping data access from legistimate user to target server by sniffing the data channel.
\* Once a new data packet is captured,it will duplicate it into its current data-knowledge set.
\* We don't guarantee every new data packets can be captured by attacker, it only has the opportuity to get each packets.
\* Variables changed: <DataKnowledge,CapDataMsg>

\*Slect a new (which means unknown to attacker till now) data packets being sent from user to FireWall
\* to simulate a successful sniff. 
SelectNewDataMsg(MsgQ,known) ==
    IF known # {}
    THEN   \* The aim of capturing  user data access packets is to get the exposure service info about the target server
           \* so (dIP,dPort) is the key knowledge.
    CHOOSE S \in SUBSET Seq2Set(MsgQ) : (\A x \in S: (\A y \in known: (x.dIP # y.dIP /\ x.dPort # y.dPort)))
    ELSE             
    Seq2Set(MsgQ)  


AttackerSniffDataChannel ==
    /\ aState = "Listen"
    /\ PureChannel(FwDataChannel) # <<>> \*pre-condition: there exists attacker unknown target server service info.
    /\ LET l == PureChannel(FwDataChannel)
       IN  /\ \E i \in 1..Len(l) :
             ( \A x \in CapDataMsg : /\ l[i].dIP # x.dIP   
                                     /\ l[i].dPort # x.dPort
                                     /\ l[i].Flg = "TCP_SYN" \* A new TCP SYN packets represents a new starting data access session. 
             )
           /\ DataKnowledge' = DataKnowledge \cup  \*post-condition: attacker learned new intelligence by a successful sniffing.
                               SelectNewDataMsg(l,CapDataMsg)
           /\ CapDataMsg' = CapDataMsg \cup   \* All the captured packets in history recorded in Log.
                               SelectNewDataMsg(l,CapDataMsg)
    /\ sniffCount' = sniffCount + 1 \* increase statistics 
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars           
    /\ UNCHANGED fw_vars
    /\ UNCHANGED server_vars
    /\ UNCHANGED <<aState, AuthKnowledge,  aSession, aTCPLinkSet, CapAuthMsg, aCounter, aIP>>
    /\ UNCHANGED Public_vars
    

\* Action 10: AttackerSpoofAuth
\* Attacker build and send fake SPA messages to SDP controller by spoofing legistimate user.
\* The making of each fake message is based on one corrsponding element in the Auth-Knowledge set, one element in the knowledge set
\* can only be used to produce one spoof message.
\* The spoof message re-use the legistimate user's ID and all other fields except SN (Tstamp) field increasing to avoid anti-replay check.  
\* Variables changed: <aSession,AuthChannel,AuthKnowledge>

\*make a spoof message according a captured auth knowledge
SpoofAuthMsg(m) ==
    [MsgID   |-> "SPA_AUTH", 
     sIP     |-> m.sIP, 
     sPort   |-> m.sPort, 
     dIP     |-> m.dIP, 
     dPort   |-> m.dPort, 
     ClientID|-> m.ClientID, 
     Tstamp |-> m.Tstamp + 1, \*SN number increase
     CliIP   |-> m.CliIP,
     CliPort |-> m.CliPort,
     SvrIP   |-> m.SvrIP,
     SvrPort |-> m.SvrPort,   
     HMAC    |-> m.HMAC,
     Type    |->"Attacker"]

 
AttackerSpoofAuth ==
   /\ AuthKnowledge # {} \* pre-condition: there exists intellicence about user's auth message learned by sniffing. 
   /\ AuthChannel' = Append(AuthChannel, SpoofAuthMsg(CHOOSE x \in AuthKnowledge: TRUE)) \* send new built spoof auth message to SDP controller 
   /\ aSession' = aSession \cup {SpoofAuthMsg(CHOOSE x \in AuthKnowledge: TRUE)} \* new Attack session is recorded in log
   /\ AuthKnowledge' = AuthKnowledge \ {CHOOSE x \in AuthKnowledge: TRUE} \* one knowledge item can be only be consumed to build one attack session
   /\ UNCHANGED user_vars
   /\ UNCHANGED sdpsvr_vars
   /\ UNCHANGED fw_vars
   /\ UNCHANGED server_vars
   /\ UNCHANGED <<aState, aTCPLinkSet, sniffCount, CapAuthMsg, aCounter, aIP,DataKnowledge, CapDataMsg>>   
   /\ UNCHANGED <<uChannel,FwCtlChannel,FwDataChannel,aChannel,sChannel>>


\* Action 11: AttackerReplayAuth
\* Attacker build and send fake SPA messages to SDP controller by replay legistimate user's message.
\* The making of each fake message is based on one corrsponding element in the Auth-Knowledge set, one element in the knowledge set
\* can only be used to produce one replay message.
\* Variables changed: <aSession,AuthChannel,AuthKnowledge>

ReplayAuthMsg(m) == \* make replay message by duplication.
    [MsgID   |-> "SPA_AUTH", 
     sIP     |-> m.sIP, 
     sPort   |-> m.sPort, 
     dIP     |-> m.dIP, 
     dPort   |-> m.dPort, 
     ClientID|-> m.ClientID, 
     Tstamp |-> m.Tstamp,
     CliIP   |-> m.CliIP,
     CliPort |-> m.CliPort,
     SvrIP   |-> m.SvrIP,
     SvrPort |-> m.SvrPort,  
     HMAC    |-> m.HMAC,
     Type    |->"Attacker"]
        

AttackerReplayAuth ==
   /\ AuthKnowledge # {}   \* pre-condition: there exists intellicence about user's auth message learned by sniffing.
   /\ AuthChannel' = Append(AuthChannel, ReplayAuthMsg(CHOOSE x \in AuthKnowledge: TRUE)) \* send new built replay auth message to SDP controller
   /\ aSession' = aSession \cup {ReplayAuthMsg(CHOOSE x \in AuthKnowledge: TRUE)} \* new Attack session is recorded in log
   /\ AuthKnowledge' = AuthKnowledge \ {CHOOSE x \in AuthKnowledge: TRUE} \* one knowledge item can be only be consumed to build one attack session
   /\ UNCHANGED user_vars
   /\ UNCHANGED sdpsvr_vars
   /\ UNCHANGED fw_vars
   /\ UNCHANGED server_vars
   /\ UNCHANGED <<aState, aTCPLinkSet, sniffCount, CapAuthMsg, aCounter, aIP, DataKnowledge, CapDataMsg>>
   /\ UNCHANGED <<uChannel,FwCtlChannel,FwDataChannel,aChannel,sChannel>>
   

\* Action 12: AttackerBrutalAttck
\* Attacker try to brutally connect the target server only by the intelligence got from user's Auth message.
\* The making of each tcp connection is based on one auth atttack session, one element in the history auth attack session set
\* can only be used to produce one brutal attack message.
\* Variables changed: <aSession,AuthChannel,AuthKnowledge,FwDataChannel>
   
AttckerBuildTcpSynPktByAuthMsg(m) == \* attack try to connect target service server as a TCP client, send SYN packet in the first step
    [sIP      |-> aIP,
     sPort    |-> SelLocalPort(aCounter,ATTACKER_BASEPORT), \* Local port increased each attack session.
     dIP      |-> m.SvrIP,  \* target server info directly get from previously auth message m. 
     dPort    |-> m.SvrPort, 
     Flg      |-> "TCP_SYN", 
     Type     |-> "Attacker"]     

Get_aSession4Battck == \* choose an historic auth attack session to make a brutal data access attack 
    CHOOSE x \in aSession: (\A y \in aTCPLinkSet: x.Tstamp # y.AuthID)
    
AttackerBrutalAttck ==
   /\ \E x \in aSession: (\A y \in aTCPLinkSet: x.Tstamp # y.AuthID)   
   /\ aCounter' = aCounter + 1  \* acounter is used to build the local port value of the TCP connection, increase each time to avoid conflict among different TCP links 
   /\ LET p == AttckerBuildTcpSynPktByAuthMsg(Get_aSession4Battck) 
      IN  /\ FwDataChannel' = Append(FwDataChannel, p) \* Transport TCP SYN packet to FireWall
          /\ aTCPLinkSet' = aTCPLinkSet \cup {   \* maintain local TCP socket
                [sIP      |-> p.sIP,
                 sPort    |-> p.sPort,
                 dIP      |-> p.dIP,
                 dPort    |-> p.dPort,
                 State    |-> "SYN_SENT",  \* the tcp link's state now is SYN_SENT
                 AuthID   |-> Get_aSession4Battck.Tstamp \* this field is used to relate to the corresponding auth attack session.        
                ] }
   /\ UNCHANGED user_vars
   /\ UNCHANGED sdpsvr_vars
   /\ UNCHANGED fw_vars
   /\ UNCHANGED server_vars
   /\ UNCHANGED <<aState, AuthKnowledge, aSession, sniffCount, CapAuthMsg, aIP, DataKnowledge, CapDataMsg>>
   /\ UNCHANGED <<uChannel,AuthChannel,FwCtlChannel,aChannel,sChannel>>
   
 
\* Action 13: AttackerProbeSvr
\* Attacker try to connect target server according to intelligence of previously captured data plane traffic info by sending TCP SYN packet.
\* The making of each tcp connection is based on one element in the Data Knowledge set which is learned by sniffing legistimate user's data access packets
\* with target server.
\* one knowledge can only be used to produce one inspection attempt.
\* Variables changed: <aCounter,FwDataChannel,aTCPLinkSet,DataKnowledge>
   
AttckerBuildTcpSynPktByData(p) ==
    [sIP      |-> aIP,
     sPort    |-> SelLocalPort(aCounter,ATTACKER_BASEPORT),
     dIP      |-> p.dIP,
     dPort    |-> p.dPort, 
     Flg      |-> "TCP_SYN", 
     Type     |-> "Attacker"]  
   
AttackerProbeSvr ==
    /\ DataKnowledge # {}  \*pre-condition: there exists learned data knowledge that still not used to launch a service probe attack.
    /\ aCounter' = aCounter + 1 \* acounter is used to build the local port value of the TCP connection, increase each time to avoid conflict among different TCP links 
    /\ LET p == AttckerBuildTcpSynPktByData(CHOOSE x \in DataKnowledge: TRUE)
       IN  /\ FwDataChannel' = Append(FwDataChannel, p) \* Transport TCP SYN packet to FireWall
           /\ aTCPLinkSet' = aTCPLinkSet \cup { \* maintain local TCP socket
                  [sIP      |-> p.sIP,
                   sPort    |-> p.sPort,
                   dIP      |-> p.dIP,
                   dPort    |-> p.dPort,
                   State    |-> "SYN_SENT",  \* the tcp link's state now is SYN_SENT
                   AuthID   |-> UNKNOWN_AUTH_ID  \* This tcp connection is built accroding to captured data plane traffic from user, attacker don't which Auth session it relates to       
                  ] } 
    /\ DataKnowledge' = AuthKnowledge \ {CHOOSE x \in DataKnowledge: TRUE} \* one knowledge item can be only be consumed to build one attack session
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED fw_vars
    /\ UNCHANGED server_vars
    /\ UNCHANGED <<aState, AuthKnowledge, aSession, sniffCount, CapAuthMsg, aIP, CapDataMsg>>
    /\ UNCHANGED <<uChannel,AuthChannel,FwCtlChannel,aChannel,sChannel>>  


\* Action 14: AttackerRcvSynAck
\* Attacker's inspection TCP connection estalished trigered by receiving TCP SYN ACK pakcet from target server.
\* This indicates the attacker fufilled a inspection attack to the target server.
\* Because the Firewall dose not filter server to endpoint direction packets, so to simplify the model, the server direcly sent TCP packets to
\* uChannel or aChannel to simplify the model.
\* Variables changed: <aTCPLinkSet,aChannel,FwDataChannel>
AttackerRcvSynAck ==
    /\ aTCPLinkSet # {}
    /\ aChannel # <<>>
    /\ Head(aChannel).Flg  = "TCP_SYN_ACK" 
    /\ Head(aChannel).Type = "Attacker"
    /\ HasMatchLink(Head(aChannel),aTCPLinkSet) 
    /\ GetMatchLink(Head(aChannel),aTCPLinkSet).State = "SYN_SENT"  \*pre-condition: local TCP client in the middle of handshake procedure
    /\ LET l == GetMatchLink(Head(aChannel),aTCPLinkSet)
       IN  aTCPLinkSet' = (aTCPLinkSet \ {l})  \* Post-condition: The matched TCP link established.
                      \cup { [sIP      |-> l.sIP,
                              sPort    |-> l.sPort,
                              dIP      |-> l.dIP,
                              dPort    |-> l.dPort,
                              State    |-> "ESTABLISHED",
                              AuthID   |-> l.AuthID   
                             ]   
                           }
    /\ aChannel' = Tail(aChannel)
    /\ FwDataChannel' = Append(FwDataChannel, EndPointBuildTcpAckPkt(Head(aChannel),"Attacker")) \* Post-condition: Client send back the final ACK packet to server.
    /\ UNCHANGED user_vars
    /\ UNCHANGED sdpsvr_vars
    /\ UNCHANGED fw_vars
    /\ UNCHANGED <<aState, AuthKnowledge,  aSession, sniffCount, CapAuthMsg, aCounter, aIP, DataKnowledge, CapDataMsg>>
    /\ UNCHANGED server_vars 
    /\ UNCHANGED <<uChannel,AuthChannel,FwCtlChannel,sChannel>> 


(***************************************************************************)
(* `^                                                                      *)
(*  The init description of the whole system                               *)
(* ^'                                                                      *)
(***************************************************************************) 
Init == /\ UsrInit
        /\ SDPSvrInit
        /\ FwInit
        /\ AttackerInit
        /\ ServerInit                

(***************************************************************************)
(* `^                                                                      *)
(*  Next state transtion of the whole system                               *)
(* ^'                                                                      *)
(***************************************************************************)
\* The next state actions of the whole system is the disjunction of each entity's next state action.
Next == \*User's next state actions
        \/ UsrConnectServerEnhance
        \/ UsrRcvSynAck
        \/ UsrReConnectServer
        \* SDP controller's next state actions
        \/ SDPSvrProcSpaAuthEx
        \* Fire Wall's next state actions 
        \/ FwProcAclCfg
        \/ FwProcEndPointAccessEx
        \* Attacker's next state actions
        \/ AttackerSniffAuthChannel
        \/ AttackerSpoofAuth
        \/ AttackerReplayAuth
        \/ AttackerBrutalAttck
        \/ AttackerSniffDataChannel
        \/ AttackerProbeSvr
        \/ AttackerRcvSynAck
        \* Target service server's next state actions
        \/ ServerRcvTCPSyn
        \/ ServerRcvTcpAck
          
(***************************************************************************)
(* `^                                                                      *)
(*  The specification of the whole system                                  *)
(* ^'                                                                      *)
(***************************************************************************)
Spec == Init /\ [][Next]_vars                                                    

(***************************************************************************)
(* `^                                                                      *)
(*  The  Fair specification of the whole system                            *)
(* ^'                                                                      *)
(***************************************************************************)
FairSpec == \*WF means weak fairness, gurantee once the action is enabled, it will be triggered sooner or later. 
    /\ Spec \* Use the fairness attribute to eliminate unnecessary stuttering states. 
    /\ WF_vars(UsrConnectServerEnhance)
    /\ WF_vars(UsrRcvSynAck)
    /\ WF_vars(UsrReConnectServer)  
    /\ WF_vars(SDPSvrProcSpaAuthEx) 
    /\ WF_vars(FwProcAclCfg)
    /\ WF_vars(AttackerSniffAuthChannel) 
    /\ WF_vars(AttackerSpoofAuth)
    /\ WF_vars(AttackerReplayAuth)
    /\ WF_vars(FwProcEndPointAccessEx)
    /\ WF_vars(ServerRcvTCPSyn) 
    /\ WF_vars(ServerRcvTcpAck)
    /\ WF_vars(AttackerBrutalAttck)
    /\ WF_vars(AttackerSniffDataChannel)
    /\ WF_vars(AttackerProbeSvr) 
    /\ WF_vars(AttackerRcvSynAck)   

(***************************************************************************)
(* `^                                                                      *)
(*  Invariants to be verified                                              *)
(* ^'                                                                      *)
(***************************************************************************)
DataAccessSafeLaw ==   \* attacker can not find target server service at anytime
   /\ \A x \in aTCPLinkSet:  x.State # "ESTABLISHED" 
   
SPASafeLaw ==  \* attacker can not launch a successful SPA auth at anytime
   /\ \A x \in SDPSucSession:  x.Type # "Attacker" 

                
(***************************************************************************)
(* `^                                                                      *)
(*  The temporal properties of the system to be verified                   *)
(* ^'                                                                      *)
(***************************************************************************)
\* Temporal Property 1: SPA_AvailableProperty
\* This formula asserts the availability of SPA service provided by the SDP controller

AuthMessageMatch(m,n) == \* Both m and n are auth Sessions
    /\ m.MsgID = n.MsgID
    /\ m.sIP = n.sIP
    /\ m.sPort = n.sPort
    /\ m.dIP = n.dIP
    /\ m.dPort = n.dPort
    /\ m.ClientID = n.ClientID
    /\ m.Tstamp = n.Tstamp
    /\ m.SvrIP = n.SvrIP 
    /\ m.SvrPort = n.SvrPort
    /\ m.HMAC = n.HMAC
    /\ m.Type = n.Type
    
SDP_AclRuleMatchAuth(m,r) == \* m is an auth Session, r is a ACL Rule
    /\ DeCrypt(m.CliIP,GetKey(m.ClientID,Account)) = r.sIP
    /\ DeCrypt(m.CliPort,GetKey(m.ClientID,Account)) = r.sPort
    /\ DeCrypt(m.SvrIP,GetKey(m.ClientID,Account)) = r.dIP
    /\ DeCrypt(m.SvrPort,GetKey(m.ClientID,Account)) = r.dPort
    /\ r.protocol = "TCP"
    /\ r.action = "Accept"

\* This formula asserts that the system's behavior eventually always meets the underlying propositions
\* 1. All authentication sessions launched by legistimate users have been successfully processed by SDP controller.
\* 2. All successfully processed Auth sessions recorded by SDP controller are sessions launched by legistimate users.
 \*3. For all sucessfully authenticated sessions, the Fire wall has been configed corresponding ACL Rule.
SPA_AvailableProperty == 
    <>[] ( /\ \A x \in uAuthSession: (\E y \in SDPSucSession: AuthMessageMatch(x,y)) \* user -> controller consistence
           /\ \A x \in SDPSucSession:(\E y \in uAuthSession:  AuthMessageMatch(x,y)) \* controller -> user consistence
           /\ \A x \in uAuthSession: (\E y \in (AclRuleSet \cup AgedRuleSet): SDP_AclRuleMatchAuth(x,y)) \* Auth session-> Acl rule consistence
         )


\* Temporal Property 2: SPA_AntiDosProperty
\* This formula asserts the Anti-Dos property of SDP controller,which means the controller 
\* can always inspect and defeat spoof and replay attack.

\* The following formula asserts that every SPA replay attack inspected by the SDP controller is originated from the attacker        
SPA_AntiReplayProperty == \A x \in ReplaySession: (\E y \in aSession: AuthMessageMatch(x,y))
    
\* The following formula asserts that every SPA spoof attack inspected by the SDP controller is originated from the attacker       
SPA_AntiSpoofProperty == \A x \in SpoofSession: (\E y \in aSession: AuthMessageMatch(x,y))

\* The following formula asserts that the system's behavior eventually always meets the underlying propositions 

\* IF attacker ever captured legistimate SPA packets by sniffing,then:
\* 1. For every captured legistimate SPA messages, the attacker will launch a SPA attack according to the message info.
\* 2. Every SPA attack message launched by the attacker will be inspected and blocked by the SDP controller.
\*  
\* IF attacker never captured legistimate SPA packets, then no SPA attack is lanched.    
SPA_AntiDosProperty ==
    <>[] ( /\ CapAuthMsg \subseteq uAuthSession
           /\ Cardinality(CapAuthMsg) = Cardinality(aSession)        
           /\ \A x \in aSession: (\E y \in (ReplaySession \cup SpoofSession): AuthMessageMatch(x,y))
           /\ SPA_AntiReplayProperty
           /\ SPA_AntiSpoofProperty          
         )    

CliSvrLinkMatch(c,s) ==
    /\ c.dIP = s.sIP
    /\ c.sIP = s.dIP
    /\ c.dPort = s.sPort
    /\ c.sPort = s.dPort
      
\* Temporal Property 3: UserAccessAvailProperty
\* This formula asserts the availability of the data plane service ,which means 
\* legistimate user can finally access the target server except the case that 3 tuple Acl Rule is aged before th TCP connection established.         
UserAccessAvailProperty ==
   <>[] ( /\ ( \A x \in  uTCPLinkSet:  /\ x.State = "ESTABLISHED"  \* scenario1: TCP link established, and exactly matched Acl Rule available in FW.  
                                       /\ \E y \in sTCPLinkSet: (CliSvrLinkMatch(x,y) /\ x.State = y.State)
                                       /\ AclMatch4Tuple(x,AclRuleSet) 
             )
          /\ uTCPLinkSet # {}
        )
                  
\* Temporal Property 4: SvrHidenProperty
\* This formula asserts the service hidden property of the SDP arhitecture. which means 
\*  finally attacker can not establish any link with the target server.
SvrHidenProperty ==
   <>[] ( /\ (\A x \in sTCPLinkSet: /\ x.Type # "Attacker" 
                                    /\ x.State = "ESTABLISHED") \*All the established link in server side are not belongs to attacker.                               
          /\ (\A y \in aTCPLinkSet: /\ y.State # "ESTABLISHED") \* Attacker as a TCP client, no established TCP link with traget server.
        )


\* Temporal Property 5: FwRuleConsistentProperty
\* This formula asserts that for each successful auth session in history there exists 
\*  a corresponding 3 Tuple Acl Rule on FW, available or aged, vice versa.

Get3TupleAclRuleSet(S) ==
(*************************************************************************)
(* get all the 3 Tpule Acl rule in history.                          *)
(*************************************************************************)
LET filtered == { e1 \in S : e1.sPort = MATCH_ANY }
IN {e1 : e1 \in filtered}


AuthRelateAcl(s,R) ==
    \E r \in R: SDP_AclRuleMatchAuth(s,r)
               
                
AclRelateAuth(r,S) ==
    \E s \in S: SDP_AclRuleMatchAuth(s,r)                 


FwRuleConsistentProperty == \* the consistent between user's SPA session and ever configed L3 tuple Acl Rule on Fire Wall 
   <>[] ( /\ Cardinality(uAuthSession) = Cardinality(AclRuleSet)   
          /\ \A x \in uAuthSession: AuthRelateAcl(x,AclRuleSet)
          /\ \A y \in AclRuleSet: AclRelateAuth(y,uAuthSession)
          /\ AgedRuleSet = {} 
        )


\* Temporal Property 6: FwCorrectProperty
\* This formula asserts that the Fire Wall's Packets filitering function works well, which means 
\* that for any unestablished TCP links there must exists packets dropping by FireWall.
                          
WithOutDropPkts(x) == ~ WithDropPkts(x)   
             
FwCorrectProperty ==\*to simplify the model, we don't consider TCP packets re-transport mechanism for attacker, 
                    \* so attacker established TCP links without packet dropping.
                    \* But for a legistimate user, its first TCP SYN packets might be routed to the FW before the corresponding ACL Rule is configed,
                    \* so commonly, this TCP link should be established by the retransmit of SYN packet after the rule is configed.
  <>[] (  /\ \A x \in aTCPLinkSet:  IF x.State = "ESTABLISHED" 
                                    THEN
                                    WithOutDropPkts(x)
                                    ELSE
                                    WithDropPkts(x)                                 
          /\ \A x \in uTCPLinkSet:  IF (x.State = "ESTABLISHED" /\ x.Retrans = FALSE)
                                    THEN
                                    WithOutDropPkts(x)
                                    ELSE
                                    WithDropPkts(x)   
       )          
 
=============================================================================
\* Modification History
\* Last modified Tue Jan 17 10:20:38 CST 2023 by 10227694
\* Created Mon Jan 17 16:29:42 CST 2022 by 10227694
