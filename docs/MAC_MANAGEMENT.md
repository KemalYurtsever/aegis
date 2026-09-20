# Local Windows MAC management

Open **Security workbench → Local utilities → MAC yönetimi**. Select the local connection, enter a unicast MAC manually or click **Rastgele üret**, then click **Uygula**. To restore the factory address, select **Fabrika adresine dön** and click **Uygula**. There is no separate preview step or confirmation checkbox. Random generation alone does not change the network.

The API is ADMIN-only. Actual changes require the native Windows API to be elevated. The Uygula click prepares and applies the exact requested address automatically; the API acknowledgement is sent by that action rather than by an extra UI step. If the API is not elevated, click **Yönetici scriptini indir**, then run the downloaded change script in an Administrator PowerShell window. A rollback script remains available after preparing or applying a change. Scripts are private operator artifacts containing the selected adapter identity; do not publish them or network screenshots. Nothing is automatically committed or uploaded.

Only adapters whose driver exposes `NetworkAddress` can be changed. Exposing that property is not proof the driver will accept every address: the active MAC is checked after restart, and mismatches are reported as unverified. Missing permanent addresses disable factory restoration. A Docker/Linux backend reports unsupported rather than attempting to change the Windows host.

Changes restart the selected adapter and may disconnect its network or trigger a different DHCP lease. Stale previews are rejected. No automatic MAC rotation, packet injection, firewall bypass or ban-avoidance claim is made. Docker Desktop traffic can appear on the LAN through the Windows physical adapter; this control does not assign a container MAC or modify a registered remote asset.

The one-click UI obtains the server-issued, signed plan token internally and applies it without another user step. The token expires after five minutes and is consumed before the driver operation starts, including when that operation fails or its result is unknown. Plan state is bounded and process-local; every Uygula click creates a fresh plan. This local prototype feature is not a distributed MAC-management service. Downloaded scripts are separate privileged operator actions, not API-token-based requests.

## MAC seen by the target

This panel changes the selected physical Windows connection globally, not only Aegis scan traffic. Choose the connection actually used to reach the target. On the same Layer-2 network/VLAN, the target can see that connection's changed source MAC. Across routers, the target sees its local next-hop router's MAC, not the scanner's original MAC. Verify the actual source on a target-side capture; that end-to-end test has not been performed during development.

The existing scanner mixes raw SYN discovery with TCP-connect version detection and application probes. Nmap's `--spoof-mac` affects raw Ethernet packets only, not version detection or NSE: [Nmap documentation](https://nmap.org/book/man-bypass-firewalls-ids.html). Adding that flag instead of changing the actual outgoing connection would not satisfy a single source MAC for the whole workflow.

Docker Desktop uses a virtual network and host networking backend: [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/). Assigning a container MAC does not establish the MAC used on the physical LAN; [macvlan is unsupported on Docker Desktop for Windows](https://docs.docker.com/engine/network/drivers/macvlan/).

If MAC selection must later be isolated to scan traffic instead of the whole local PC connection, a dedicated directly LAN-connected scanner interface is needed (for example, a bridged Linux/Kali VM with a supported virtual/physical adapter). Every scan and enrichment tool must use that worker. Bridging support depends on the hypervisor, adapter and network; it must be tested, not assumed. That remote-worker architecture is not implemented by this host control. No host adapter was changed during development.

Windows operations use the driver's advanced property object, not arbitrary registry paths or shell text: [Set-NetAdapterAdvancedProperty](https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapteradvancedproperty), [Reset-NetAdapterAdvancedProperty](https://learn.microsoft.com/en-us/powershell/module/netadapter/reset-netadapteradvancedproperty), and [Restart-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/restart-netadapter).
