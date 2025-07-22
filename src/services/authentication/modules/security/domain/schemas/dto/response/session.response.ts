export interface SessionResponse {
  sessionId: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  ipAddress: string;
  location: {
    country: string;
    city: string;
    region: string;
  };
}
