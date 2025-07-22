import {
  Body,
  Controller,
  Get,
  Inject,
  Logger,
  OnModuleInit,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { Request } from 'express';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { SignInRequest } from '../../domain/schemas/dto/request/signin.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { SignUpRequest } from '../../domain/schemas/dto/request/signup.request';
import { CreateLogsNotificationsRequest } from 'src/services/notifications/modules/notifications/domain/schemas/dto/request/create.logs-notifications.request';
import { statusCode } from 'src/settings/environments/status-code';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';
import { Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import axios from 'axios';
import { SessionResponse } from '../../domain/schemas/dto/response/session.response';
import { VerifyTokenRequest } from '../../domain/schemas/dto/request/verify-token.request';
import { RefreshTokenResponse } from '../../domain/schemas/dto/response/refresh-token.response';

@Controller('auth')
@ApiTags('Authentication')
export class AuthGatewayController implements OnModuleInit {
  private readonly logger: Logger = new Logger(AuthGatewayController.name);
  constructor(
    @Inject(environments.authenticationKafkaClient)
    private readonly authClient: ClientKafka,
    @Inject(environments.notificationKafkaClient)
    private readonly notificationClient: ClientKafka,
    private readonly jwtService: JwtService,
  ) {}

  async onModuleInit() {
    this.authClient.subscribeToResponseOf('auth.signin');
    this.authClient.subscribeToResponseOf('auth.signup');
    this.authClient.subscribeToResponseOf('auth.verify-token');
    this.authClient.subscribeToResponseOf('auth.findUserByEmail');
    this.authClient.subscribeToResponseOf('auth.currentUser');
    this.authClient.subscribeToResponseOf('auth.get-session');
    this.authClient.subscribeToResponseOf('auth.refresh-token');
    await this.authClient.connect();
    console.log(this.authClient['responsePatterns']);
  }

  @Post('signin')
  @ApiOperation({
    summary: 'Sign in a user',
    description:
      'This endpoint allows a user to sign in using their credentials.',
  })
  async signin(
    @Req() request: Request,
    @Body() signInRequest: SignInRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(
        `Received sign-in request for user: ${signInRequest.email}`,
      );
      const tokenResponse = (await sendKafkaRequest(
        this.authClient.send('auth.signin', signInRequest),
      )) as { idUser?: string; [key: string]: any };

      res.cookie('auth_token', tokenResponse.accessToken, {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none', // 'lax' is a good default for CSRF protection
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      });

      res.cookie('refresh_token', tokenResponse.refreshToken, {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none', // 'lax' is a good default for CSRF protection
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      });

      const clientIp =
        request.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
        request.socket.remoteAddress;

      const notification: CreateLogsNotificationsRequest = {
        log: 'User signed in successfully',
        message: `User with email ${signInRequest.email} signed in successfully.`,
        subject: 'User Sign In',
        phone: '+593994532438',
        email: signInRequest.email,
        module: 'Authentication Module',
        eventType: 'sign_in',
        userId:
          typeof tokenResponse.idUser === 'number' ? tokenResponse.idUser : '',
        userEmail: signInRequest.email,
        ipAddress: clientIp,
        userAgent: request.headers['user-agent'],
        statusCode: statusCode.SUCCESS,
        kafkaTopic: 'auth.signin',
        correlationId: Array.isArray(request.headers['x-correlation-id'])
          ? request.headers['x-correlation-id'][0]
          : request.headers['x-correlation-id'] || '',
      };

      this.notificationClient.emit(
        'notification.send-and-create',
        notification,
      );
      this.logger.log(
        `Notification sent for user sign-in: ${signInRequest.email}`,
      );

      this.logger.log(`Sign-in successful for user: ${signInRequest.email}`);
      return new ApiResponse(
        'User signed in successfully',
        tokenResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('signup')
  @ApiOperation({
    summary: 'Sign up a new user',
    description:
      'This endpoint allows a new user to sign up and create an account.',
  })
  async signup(
    @Req() request: Request,
    @Body() signUpRequest: SignUpRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(
        `Received sign-up request for user: ${signUpRequest.userEmail}`,
      );
      const clientIp =
        request.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
        request.socket.remoteAddress;
      const tokenResponse = (await sendKafkaRequest(
        this.authClient.send('auth.signup', signUpRequest),
      )) as {
        idUser?: string;
        [key: string]: any;
      };

      res.cookie('auth_token', tokenResponse.accessToken, {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      });

      res.cookie('refresh_token', tokenResponse.refreshToken, {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      });

      const notification: CreateLogsNotificationsRequest = {
        log: 'User signed up successfully',
        message: `User with email ${signUpRequest.userEmail} signed up successfully.`,
        subject: 'User Sign Up',
        phone: '+593994532438',
        email: signUpRequest.userEmail,
        module: 'Authentication Module',
        eventType: 'sign_up',
        userId:
          typeof tokenResponse.idUser === 'number' ? tokenResponse.idUser : '',
        userEmail: signUpRequest.userEmail,
        ipAddress: clientIp,
        userAgent: request.headers['user-agent'],
        statusCode: statusCode.SUCCESS,
        kafkaTopic: 'auth.signup',
        correlationId: Array.isArray(request.headers['x-correlation-id'])
          ? request.headers['x-correlation-id'][0]
          : request.headers['x-correlation-id'] || '',
      };
      this.notificationClient.emit(
        'notification.send-and-create',
        notification,
      );
      this.logger.log(
        `Notification sent for user sign-up: ${signUpRequest.userEmail}`,
      );
      return new ApiResponse(
        'User signed up successfully',
        tokenResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('logout')
  @ApiOperation({
    summary: 'Logout a user',
    description: 'This endpoint allows a user to log out of their account.',
  })
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(`Received logout request for user`);
      // Here you would typically handle the logout logic, such as invalidating the token
      res.clearCookie('auth_token', {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none', // 'lax' is a good default for CSRF protection
        maxAge: 0, // Clear the cookie immediately
      }); // Clear the cookie

      res.clearCookie('refresh_token', {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none', // 'lax' is a good default for CSRF protection
        maxAge: 0, // Clear the cookie immediately
      }); // Clear the cookie
      this.logger.log(`User logged out successfully`);
      return new ApiResponse('User logged out successfully', null, request.url);
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('session')
  @ApiOperation({
    summary: 'Get user session',
    description: 'This endpoint retrieves the user session information.',
  })
  async getSession(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(`Received request for user session`);
      const auth_token =
        request.cookies['auth_token'] ||
        request.headers.authorization?.split(' ')[1];

      const rawIp =
        request.headers['x-forwarded-for'] || request.socket.remoteAddress;
      const ip = Array.isArray(rawIp) ? rawIp[0] : rawIp || 'Unknown';

      // Obtener ubicación
      const location = await this.lookupGeoLocation(ip.toString());

      const verifyToken: VerifyTokenRequest = new VerifyTokenRequest(
        auth_token,
        ip,
      );

      const session: SessionResponse = await sendKafkaRequest(
        this.authClient.send('auth.get-session', { verifyToken: verifyToken }),
      );

      if (!session) {
        this.logger.warn(`No session found for token: ${auth_token}`);
        throw new RpcException({
          statusCode: statusCode.NOT_FOUND,
          message: 'Session not found ❌',
        });
      }

      const currentTime = new Date();
      const expiresAtDate = new Date(session.expiresAt);
      console.log('Current time (toISOString):', currentTime.toISOString()); // UTC ISO string
      console.log('Expires at (toISOString):', expiresAtDate.toISOString()); // UTC ISO string

      console.log(
        'Current time (toLocaleString):',
        currentTime.toLocaleString(),
      ); // Local readable string
      console.log(
        'Expires at (toLocaleString):',
        expiresAtDate.toLocaleString(),
      ); // Local readable string

      let message: string = `Session for user ${session.userId} is valid until ${expiresAtDate.toLocaleString()}`;
      let code: number = 200;

      if (currentTime > expiresAtDate) {
        this.logger.warn(`Session for user ${session.userId} has expired`);
        message = `Session for user ${session.userId} has expired`;
        code = statusCode.UNAUTHORIZED;
      }

      this.logger.log(`User session retrieved successfully`);
      //res.status(code);
      return new ApiResponse(message, session, request.url, code);
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('verify-token')
  @ApiOperation({
    summary: 'Verify user token',
    description: 'This endpoint verifies the user token.',
  })
  async verifyToken(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(`Received token verification request`);
      const auth_token =
        request.cookies['auth_token'] ||
        request.headers.authorization?.split(' ')[1];

      const rawIp =
        request.headers['x-forwarded-for'] || request.socket.remoteAddress;
      const ip = Array.isArray(rawIp) ? rawIp[0] : rawIp || 'Unknown';

      // Obtener ubicación
      const location = await this.lookupGeoLocation(ip.toString());

      const verifyToken: VerifyTokenRequest = new VerifyTokenRequest(
        auth_token,
        ip,
      );

      const isValidToken: boolean = await sendKafkaRequest(
        this.authClient.send('auth.verify-token', { verifyToken: verifyToken }),
      );

      if (isValidToken === null) {
        this.logger.warn(`Invalid token received`);
        throw new RpcException({
          statusCode: statusCode.UNAUTHORIZED,
          message: 'Token is not valid or has expired ❌',
        });
      }

      const tokenDecoded = this.jwtService.decode(auth_token);

      const sessionResponse: SessionResponse = {
        sessionId: tokenDecoded['jti'] as string,
        userId: tokenDecoded['sub'] as string,
        ipAddress: ip,
        createdAt: new Date(tokenDecoded['iat'] * 1000),
        expiresAt: new Date(tokenDecoded['exp'] * 1000),
        location: location,
      };

      this.logger.log(`Token verification successful`);
      return new ApiResponse('Token is valid', sessionResponse, request.url);
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('current-user')
  @ApiOperation({
    summary: 'Get current authenticated user',
    description:
      'This endpoint retrieves the current authenticated user based on the provided JWT token.',
  })
  async getCurrentUser(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(`Received request for current user`);
      const auth_token =
        request.cookies['auth_token'] ||
        request.headers.authorization?.split(' ')[1];

      const user = await sendKafkaRequest(
        this.authClient.send('auth.currentUser', { auth_token: auth_token }),
      );

      this.logger.log(`Current user retrieved successfully`);
      return new ApiResponse(
        'Current user retrieved successfully',
        user,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('refresh-token')
  @ApiOperation({
    summary: 'Refresh user token',
    description:
      'This endpoint allows a user to refresh their authentication token.',
  })
  async refreshToken(
    @Req() request: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse> {
    try {
      this.logger.log(`Received refresh token request`);
      const refreshToken =
        request.cookies['refresh_token'] ||
        request.headers.authorization?.split(' ')[1];

      if (!refreshToken) {
        throw new RpcException({
          statusCode: statusCode.UNAUTHORIZED,
          message: 'Refresh token is missing ❌',
        });
      }

      const newTokens: RefreshTokenResponse = await sendKafkaRequest(
        this.authClient.send('auth.refresh-token', { refreshToken }),
      );

      res.cookie('auth_token', newTokens.accessToken, {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none', // 'lax' is a good default for CSRF protection
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      });

      res.cookie('refresh_token', newTokens.refreshToken, {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: true, // Set to true if using HTTPS
        sameSite: 'none', // 'lax' is a good default for CSRF protection
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      });

      this.logger.log(`Refresh token successful`);
      return new ApiResponse(
        'Tokens refreshed successfully',
        newTokens,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  private async lookupGeoLocation(ip: string): Promise<{
    country: string;
    city: string;
    region: string;
  }> {
    try {
      const response = await axios.get(`http://ip-api.com/json/${ip}`);
      const data = response.data;
      console.log(`first: ${data}`);
      return {
        country: data.country || 'Unknown',
        city: data.city || 'Unknown',
        region: data.regionName || 'Unknown',
      };
    } catch (error) {
      console.warn(`Could not fetch geo location: ${error.message}`);
      return {
        country: 'Unknown',
        city: 'Unknown',
        region: 'Unknown',
      };
    }
  }
}
