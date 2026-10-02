//! gRPC service paths. One place to update when proto packages move.

#![allow(dead_code)]

pub const AUTH_POW_CHALLENGE: &str = "/shared.proto.services.v1.AuthService/GetPowChallenge";
pub const AUTH_REGISTER: &str = "/shared.proto.services.v1.AuthService/RegisterDevice";
pub const AUTH_AUTHENTICATE: &str = "/shared.proto.services.v1.AuthService/AuthenticateDevice";
pub const AUTH_REFRESH: &str = "/shared.proto.services.v1.AuthService/RefreshToken";
pub const AUTH_LOGOUT: &str = "/shared.proto.services.v1.AuthService/Logout";
pub const DEVICE_CONFIRM_LINK: &str =
    "/shared.proto.services.v1.DeviceLinkService/ConfirmDeviceLink";
pub const KEY_GET_BUNDLE: &str = "/shared.proto.services.v1.KeyService/GetPreKeyBundle";
pub const KEY_UPLOAD: &str = "/shared.proto.services.v1.KeyService/UploadPreKeys";
pub const KEY_COUNT: &str = "/shared.proto.services.v1.KeyService/GetPreKeyCount";
pub const MESSAGING_STREAM: &str = "/shared.proto.services.v1.MessagingService/MessageStream";
pub const USER_FIND: &str = "/shared.proto.services.v1.UserService/FindUser";
pub const INVITE_ACCEPT: &str = "/shared.proto.services.v1.InviteService/AcceptInvite";
