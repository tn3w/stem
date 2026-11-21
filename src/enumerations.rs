macro_rules! string_enum {
    ($name:ident { $($variant:ident = $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant,)+
            Other(String),
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $text,)+
                    Self::Other(text) => text,
                }
            }

            pub fn is_recognized(&self) -> bool {
                !matches!(self, Self::Other(_))
            }

            pub fn known() -> &'static [Self] {
                &[$(Self::$variant,)+]
            }
        }

        impl std::str::FromStr for $name {
            type Err = std::convert::Infallible;

            fn from_str(
                text: &str,
            ) -> std::result::Result<Self, std::convert::Infallible> {
                Ok(match text {
                    $($text => Self::$variant,)+
                    other => Self::Other(other.to_string()),
                })
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl From<&str> for $name {
            fn from(text: &str) -> Self {
                text.parse().unwrap_or_else(|never| match never {})
            }
        }
    };
}

pub(crate) use string_enum;

string_enum!(Runlevel {
    Debug = "DEBUG",
    Info = "INFO",
    Notice = "NOTICE",
    Warn = "WARN",
    Err = "ERR",
});

string_enum!(Flag {
    Authority = "Authority",
    BadExit = "BadExit",
    BadDirectory = "BadDirectory",
    Exit = "Exit",
    Fast = "Fast",
    Guard = "Guard",
    HsDir = "HSDir",
    Named = "Named",
    NoEdConsensus = "NoEdConsensus",
    Running = "Running",
    Stable = "Stable",
    StaleDesc = "StaleDesc",
    Unnamed = "Unnamed",
    V2Dir = "V2Dir",
    V3Dir = "V3Dir",
    Valid = "Valid",
});

string_enum!(Signal {
    Reload = "RELOAD",
    Hup = "HUP",
    Shutdown = "SHUTDOWN",
    Int = "INT",
    Dump = "DUMP",
    Usr1 = "USR1",
    Debug = "DEBUG",
    Usr2 = "USR2",
    Halt = "HALT",
    Term = "TERM",
    Newnym = "NEWNYM",
    ClearDnsCache = "CLEARDNSCACHE",
    Heartbeat = "HEARTBEAT",
    Active = "ACTIVE",
    Dormant = "DORMANT",
});

string_enum!(CircStatus {
    Launched = "LAUNCHED",
    Built = "BUILT",
    GuardWait = "GUARD_WAIT",
    Extended = "EXTENDED",
    Failed = "FAILED",
    Closed = "CLOSED",
});

string_enum!(CircBuildFlag {
    OneHopTunnel = "ONEHOP_TUNNEL",
    IsInternal = "IS_INTERNAL",
    NeedCapacity = "NEED_CAPACITY",
    NeedUptime = "NEED_UPTIME",
});

string_enum!(CircPurpose {
    General = "GENERAL",
    HsClientIntro = "HS_CLIENT_INTRO",
    HsClientRend = "HS_CLIENT_REND",
    HsServiceIntro = "HS_SERVICE_INTRO",
    HsServiceRend = "HS_SERVICE_REND",
    Testing = "TESTING",
    Controller = "CONTROLLER",
    MeasureTimeout = "MEASURE_TIMEOUT",
    HsVanguards = "HS_VANGUARDS",
    PathBiasTesting = "PATH_BIAS_TESTING",
});

string_enum!(CircClosureReason {
    None = "NONE",
    TorProtocol = "TORPROTOCOL",
    Internal = "INTERNAL",
    Requested = "REQUESTED",
    Hibernating = "HIBERNATING",
    ResourceLimit = "RESOURCELIMIT",
    ConnectFailed = "CONNECTFAILED",
    OrIdentity = "OR_IDENTITY",
    OrConnClosed = "OR_CONN_CLOSED",
    Finished = "FINISHED",
    Timeout = "TIMEOUT",
    Destroyed = "DESTROYED",
    NoPath = "NOPATH",
    NoSuchService = "NOSUCHSERVICE",
    MeasurementExpired = "MEASUREMENT_EXPIRED",
});

string_enum!(CircEvent {
    PurposeChanged = "PURPOSE_CHANGED",
    Cannibalized = "CANNIBALIZED",
});

string_enum!(HiddenServiceState {
    HsciConnecting = "HSCI_CONNECTING",
    HsciIntroSent = "HSCI_INTRO_SENT",
    HsciDone = "HSCI_DONE",
    HscrConnecting = "HSCR_CONNECTING",
    HscrEstablishedIdle = "HSCR_ESTABLISHED_IDLE",
    HscrEstablishedWaiting = "HSCR_ESTABLISHED_WAITING",
    HscrJoined = "HSCR_JOINED",
    HssiConnecting = "HSSI_CONNECTING",
    HssiEstablished = "HSSI_ESTABLISHED",
    HssrConnecting = "HSSR_CONNECTING",
    HssrJoined = "HSSR_JOINED",
});

string_enum!(RelayEndReason {
    Misc = "MISC",
    ResolveFailed = "RESOLVEFAILED",
    ConnectRefused = "CONNECTREFUSED",
    ExitPolicy = "EXITPOLICY",
    Destroy = "DESTROY",
    Done = "DONE",
    Timeout = "TIMEOUT",
    NoRoute = "NOROUTE",
    Hibernating = "HIBERNATING",
    Internal = "INTERNAL",
    ResourceLimit = "RESOURCELIMIT",
    ConnReset = "CONNRESET",
    TorProtocol = "TORPROTOCOL",
    NotDirectory = "NOTDIRECTORY",
});

string_enum!(StreamStatus {
    New = "NEW",
    NewResolve = "NEWRESOLVE",
    Remap = "REMAP",
    SentConnect = "SENTCONNECT",
    SentResolve = "SENTRESOLVE",
    Succeeded = "SUCCEEDED",
    Failed = "FAILED",
    Detached = "DETACHED",
    Closed = "CLOSED",
    ControllerWait = "CONTROLLER_WAIT",
    XoffSent = "XOFF_SENT",
    XoffRecv = "XOFF_RECV",
    XonSent = "XON_SENT",
    XonRecv = "XON_RECV",
});

string_enum!(StreamClosureReason {
    Misc = "MISC",
    ResolveFailed = "RESOLVEFAILED",
    ConnectRefused = "CONNECTREFUSED",
    ExitPolicy = "EXITPOLICY",
    Destroy = "DESTROY",
    Done = "DONE",
    Timeout = "TIMEOUT",
    NoRoute = "NOROUTE",
    Hibernating = "HIBERNATING",
    Internal = "INTERNAL",
    ResourceLimit = "RESOURCELIMIT",
    ConnReset = "CONNRESET",
    TorProtocol = "TORPROTOCOL",
    NotDirectory = "NOTDIRECTORY",
    End = "END",
    PrivateAddr = "PRIVATE_ADDR",
});

string_enum!(StreamSource {
    Cache = "CACHE",
    Exit = "EXIT",
});

string_enum!(StreamPurpose {
    DirFetch = "DIR_FETCH",
    DirUpload = "DIR_UPLOAD",
    DnsRequest = "DNS_REQUEST",
    DirPortTest = "DIRPORT_TEST",
    User = "USER",
});

string_enum!(OrStatus {
    New = "NEW",
    Launched = "LAUNCHED",
    Connected = "CONNECTED",
    Failed = "FAILED",
    Closed = "CLOSED",
});

string_enum!(OrClosureReason {
    Done = "DONE",
    ConnectRefused = "CONNECTREFUSED",
    Identity = "IDENTITY",
    ConnectReset = "CONNECTRESET",
    Timeout = "TIMEOUT",
    NoRoute = "NOROUTE",
    IoError = "IOERROR",
    ResourceLimit = "RESOURCELIMIT",
    Misc = "MISC",
    PtMissing = "PT_MISSING",
});

string_enum!(AuthDescriptorAction {
    Accepted = "ACCEPTED",
    Dropped = "DROPPED",
    Rejected = "REJECTED",
});

string_enum!(StatusType {
    General = "GENERAL",
    Client = "CLIENT",
    Server = "SERVER",
});

string_enum!(GuardType {
    Entry = "ENTRY",
});

string_enum!(GuardStatus {
    New = "NEW",
    Up = "UP",
    Down = "DOWN",
    Bad = "BAD",
    Good = "GOOD",
    Dropped = "DROPPED",
});

string_enum!(TimeoutSetType {
    Computed = "COMPUTED",
    Reset = "RESET",
    Suspended = "SUSPENDED",
    Discard = "DISCARD",
    Resume = "RESUME",
});

string_enum!(ConnectionType {
    Or = "OR",
    Dir = "DIR",
    Exit = "EXIT",
});

string_enum!(TokenBucket {
    Global = "GLOBAL",
    Relay = "RELAY",
    OrConn = "ORCONN",
});

string_enum!(HsDescAction {
    Requested = "REQUESTED",
    Upload = "UPLOAD",
    Received = "RECEIVED",
    Uploaded = "UPLOADED",
    Ignore = "IGNORE",
    Failed = "FAILED",
    Created = "CREATED",
});

string_enum!(HsDescReason {
    BadDesc = "BAD_DESC",
    QueryRejected = "QUERY_REJECTED",
    UploadRejected = "UPLOAD_REJECTED",
    NotFound = "NOT_FOUND",
    QueryNoHsDir = "QUERY_NO_HSDIR",
    QueryRateLimited = "QUERY_RATE_LIMITED",
    Unexpected = "UNEXPECTED",
});

string_enum!(HsAuth {
    NoAuth = "NO_AUTH",
    BasicAuth = "BASIC_AUTH",
    StealthAuth = "STEALTH_AUTH",
    Unknown = "UNKNOWN",
});

impl RelayEndReason {
    pub fn code(&self) -> Option<usize> {
        Self::known()
            .iter()
            .position(|reason| reason == self)
            .map(|index| index + 1)
    }
}
