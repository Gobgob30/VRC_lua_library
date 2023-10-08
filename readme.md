TODO:

<!-- #region AUTH -->

    UserExist(email, displayName, userId, excludeUsetId): bool or nil
    Login(user, password): login_cookie or “2fa” or nil
    Auth2fa(code):login_cookie or nil
    Logout(authCookie): nil
    GetCredCookie(): nil or login_cookie
    DeleteUser(authCookie): {message: string, date_submitted: string, date_deleted: string}

<!-- #endregion -->

<!-- #region Avatar -->

    GetOwnAvatar(): AvatarObject or nil
    <!-- SearchAvatars: to implement scema -->

<!-- #endregion -->
