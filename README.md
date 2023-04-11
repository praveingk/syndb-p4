# SyNDB (Synchronized Network Debugger)

This source code enables obtaining synchronized network snaphot of recent history in the network.

Paper Link :point_right:	 https://www.usenix.org/system/files/nsdi21-kannan.pdf

## Source Code Pointers

### Switch Code
The switch data-plane code is written in [P4](https://github.com/p4lang) programming language. Once this code is up and running, the virtual switches are synchronized to a global time, and start recording packets. They generate precords to the collector when the configured trigger condition is hit.

### Steps to run p4_14 based SyNDB in Tofino:

1) Navigate to the SDE PATH :
```shell
     cd ~/bf-sde-8.x.x
     export SYNDB_PATH=<PATH TO SYNDB FOLDER>
```
2) Set the env variables : 
```shell
     . ./set_sde.bash
```
3) Build the p4 program using the command :
```shell
     ./p4_build.sh $SYNDB_PATH/syndb.p4
```
4) Load the p4 program, and run the control plane API code using :
```shell
     cd $SYNDB_PATH/v_14/CP
     ./run.sh
```