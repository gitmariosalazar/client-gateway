export interface SessionResponse {
  sessionId: string;
  userId: string;
  createdAtAccessToken: Date;
  expiresAtAccessToken: Date;
  createdAtRefreshToken?: Date;
  expiresAtRefreshToken?: Date;
  ipAddress: string;
  location: {
    country: string;
    city: string;
    region: string;
  };
  refreshTokenValid?: boolean;
  accessTokenValid?: boolean;
}
