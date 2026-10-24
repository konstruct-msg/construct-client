//! gRPC service paths. One place to update when proto packages move.

#![allow(dead_code)]

pub const AUTH_POW_CHALLENGE: &str = "/shared.proto.services.v1.AuthService/GetPowChallenge";
pub const AUTH_REGISTER: &str = "/shared.proto.services.v1.AuthService/RegisterDevice";
pub const AUTH_AUTHENTICATE: &str = "/shared.proto.services.v1.AuthService/AuthenticateDevice";
pub const AUTH_REFRESH: &str = "/shared.proto.services.v1.AuthService/RefreshToken";
pub const AUTH_SET_RECOVERY_KEY: &str = "/shared.proto.services.v1.AuthService/SetRecoveryKey";
pub const AUTH_RECOVERY_STATUS: &str = "/shared.proto.services.v1.AuthService/GetRecoveryStatus";
pub const AUTH_LOGOUT: &str = "/shared.proto.services.v1.AuthService/Logout";
pub const DEVICE_PUBLISH_CERTIFICATE: &str =
    "/shared.proto.services.v1.DeviceService/PublishDeviceCertificate";
pub const DEVICE_CONFIRM_LINK: &str =
    "/shared.proto.services.v1.DeviceLinkService/ConfirmDeviceLink";
pub const KEY_GET_BUNDLE: &str = "/shared.proto.services.v1.KeyService/GetPreKeyBundle";
pub const KEY_UPLOAD: &str = "/shared.proto.services.v1.KeyService/UploadPreKeys";
pub const KEY_COUNT: &str = "/shared.proto.services.v1.KeyService/GetPreKeyCount";
pub const MESSAGING_STREAM: &str = "/shared.proto.services.v1.MessagingService/MessageStream";
pub const USER_FIND: &str = "/shared.proto.services.v1.UserService/FindUser";
pub const INVITE_ACCEPT: &str = "/shared.proto.services.v1.InviteService/AcceptInvite";
pub const KEY_GET_BUNDLES: &str = "/shared.proto.services.v1.KeyService/GetPreKeyBundles";
pub const AUTH_SENDER_CERT: &str = "/shared.proto.services.v1.AuthService/GetSenderCertificate";
pub const MESSAGING_SEND_SEALED: &str =
    "/shared.proto.services.v1.MessagingService/SendSealedMessage";
pub const SERVER_TRUST: &str = "/shared.proto.services.v1.ServerTrustService/GetServerTrust";
pub const KEY_SPK_AGE: &str = "/shared.proto.services.v1.KeyService/GetSignedPreKeyAge";
pub const KEY_ROTATE_SPK: &str = "/shared.proto.services.v1.KeyService/RotateSignedPreKey";
pub const MESSAGING_SEND: &str = "/shared.proto.services.v1.MessagingService/SendMessage";
pub const AUTH_APPROVE_JOIN: &str = "/shared.proto.services.v1.AuthService/ApproveJoinRequest";
pub const DEVICE_SUBMIT_JOIN: &str =
    "/shared.proto.services.v1.DeviceLinkService/SubmitJoinRequest";
pub const DEVICE_CHECK_JOIN: &str =
    "/shared.proto.services.v1.DeviceLinkService/CheckJoinRequestStatus";
pub const MEDIA_DOWNLOAD: &str = "/shared.proto.services.v1.MediaService/DownloadMedia";
pub const MEDIA_UPLOAD_TOKEN: &str = "/shared.proto.services.v1.MediaService/GenerateUploadToken";
pub const MEDIA_UPLOAD: &str = "/shared.proto.services.v1.MediaService/UploadMedia";
pub const DEVICE_LIST: &str = "/shared.proto.services.v1.DeviceService/ListDevices";
pub const DEVICE_REVOKE: &str = "/shared.proto.services.v1.DeviceService/RevokeDevice";
pub const USER_PROFILE: &str = "/shared.proto.services.v1.UserService/GetUserProfile";
pub const USER_UPDATE_PROFILE: &str = "/shared.proto.services.v1.UserService/UpdateUserProfile";
pub const USER_CHECK_USERNAME: &str =
    "/shared.proto.services.v1.UserService/CheckUsernameAvailability";
pub const USER_SET_DISCOVERABLE: &str = "/shared.proto.services.v1.UserService/SetDiscoverable";
pub const DEVICE_SET_METADATA: &str = "/shared.proto.services.v1.DeviceService/SetDeviceMetadata";
