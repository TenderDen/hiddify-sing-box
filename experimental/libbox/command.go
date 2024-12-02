package libbox

const (
	CommandLog int32 = iota
	CommandStatus
	CommandServiceReload
	CommandServiceClose
	CommandCloseConnections
	CommandGroup
	CommandSelectOutbound
	CommandURLTest
	CommandGroupExpand
	CommandClashMode
	CommandSetClashMode
	CommandGetSystemProxyStatus
	CommandSetSystemProxyEnabled
<<<<<<< HEAD

	CommandGroupInfoOnly//hiddify
=======
	CommandConnections
	CommandCloseConnection
	CommandGetDeprecatedNotes
>>>>>>> v1.10.3
)
