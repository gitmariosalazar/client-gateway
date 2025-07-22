export interface RefreshTokenResponse {
  idRefreshToken: string;
  idUser: string;
  idAccessToken: string;
  refreshToken: string;
  revoked: boolean;
  accessToken?: string;
  expiresAt: Date;
  createdAt?: Date;
  updatedAt?: Date;
}
