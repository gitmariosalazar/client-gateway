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
          typeof tokenResponse.idUser === 'number' ? tokenResponse.idUser : 0,
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
          typeof tokenResponse.idUser === 'number' ? tokenResponse.idUser : 0,
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
      res.clearCookie('auth_token'); // Clear the cookie
      this.logger.log(`User logged out successfully`);
      return new ApiResponse('User logged out successfully', null, request.url);
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
      const isValidToken: boolean = await sendKafkaRequest(
        this.authClient.send('auth.verify-token', { auth_token: auth_token }),
      );

      if (!isValidToken) {
        this.logger.warn(`Invalid token received`);
        throw new RpcException({
          statusCode: statusCode.UNAUTHORIZED,
          message: 'Token is not valid or has expired ❌',
        });
      }

      this.logger.log(`Token verification successful`);
      return new ApiResponse('Token is valid', isValidToken, request.url);
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
}
