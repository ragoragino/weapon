#### Weapon 
Weapon is a simple VPN written in Rust. Currently only works with TUN devices.

#### Sources
Setting up docker networks:

If running across two Docker subnets, change the default subnet for Docker on remote node:
``` 
// docker.json
{
  "default-address-pools":
  [
    {"base":"172.18.0.0/16","size":24}
  ]
}
```

Remote node config:
```
"device_configuration": {
  "device_type": "TUN",
  "address": "172.19.0.0",
  "destination": "172.16.0.0",
  "netmask": "255.254.0.0",
  "mtu": 1472
}
```

Local node config:
```
"device_configuration": {
  "device_type": "TUN",
  "address": "172.16.0.0",
  "destination": "172.18.0.0",
  "netmask": "255.254.0.0",
  "mtu": 1472
}
```

If running across two Docker subnets, allow tun0 -> docker0 traffic on both local and remote nodes:
https://docs.docker.com/network/iptables/
```
iptables -I DOCKER-USER -i tun0 -o docker0 -j ACCEPT
```

#### Sources
https://www.reddit.com/r/golang/comments/nvzcyf/is_it_possible_to_write_a_working_vpn_service_in/ \
Mastering OpenVPN: Master building and integrating secure private networks using OpenVPN \
https://community.openvpn.net/openvpn/wiki/BridgingAndRouting?__cf_chl_jschl_tk__=a3Nz8Iq8lfORY1pZ2ORJVvotU9y.GE1KuaQA1eeD.Rs-1641741448-0-gaNycGzNCH0 \
https://openvpn.net/vpn-server-resources/site-to-site-routing-explained-in-detail/ \
https://backreference.org/2010/03/26/tuntap-interface-tutorial/**** \
https://www.gabriel.urdhr.fr/2021/05/08/tuntap/ \
https://www.kernel.org/doc/Documentation/networking/tuntap.txt
