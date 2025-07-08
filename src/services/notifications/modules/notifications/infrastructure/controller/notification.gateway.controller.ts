import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  Logger,
  OnModuleInit,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { CreateNotificationRequest } from '../../domain/schemas/dto/request/create.notification.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdateNotificationRequest } from '../../domain/schemas/dto/request/update.notification.request';
import { CreateLogsNotificationsRequest } from '../../domain/schemas/dto/request/create.logs-notifications.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('notification')
@ApiTags('Notifications')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class NotificationGatewayController implements OnModuleInit {
  private readonly logger = new Logger(NotificationGatewayController.name);
  constructor(
    @Inject(environments.notificationKafkaClient)
    private readonly notificationClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.notificationClient.subscribeToResponseOf('notification.create');
    this.notificationClient.subscribeToResponseOf('notification.update');
    this.notificationClient.subscribeToResponseOf('notification.find-all');
    this.notificationClient.subscribeToResponseOf('notification.find-by-id');
    this.notificationClient.subscribeToResponseOf('notification.find-by-email');
    this.notificationClient.subscribeToResponseOf('notification.delete');
    this.notificationClient.subscribeToResponseOf(
      'notification.send-and-create',
    );
    console.log(
      'Response patterns:',
      this.notificationClient['responsePatterns'],
    );

    this.logger.log(
      'NotificationGatewayController initialized and connected to Kafka',
    );
    await this.notificationClient.connect();
  }

  @Post('send-and-create')
  @ApiOperation({
    summary: 'Method POST - Send and create a notification ✅',
    description:
      'This endpoint allows you to send a notification and create a log entry for it. It requires a complete notification object with all necessary details.',
  })
  async sendAndCreateNotification(
    @Req() request: Request,
    @Body() notification: CreateLogsNotificationsRequest,
  ): Promise<ApiResponse> {
    try {
      this.logger.log('Sending and creating notification', notification);
      const response = await sendKafkaRequest(
        this.notificationClient.send(
          'notification.send-and-create',
          notification,
        ),
      );
      return new ApiResponse(
        'Notification sent and created successfully',
        response,
        request.url,
      );
    } catch (error) {
      this.logger.error(
        'Error sending and creating notification',
        error.message,
      );
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new notification ✅',
    description:
      'This endpoint allows you to create a new notification with the required details.',
  })
  async createNotification(
    @Req() request: Request,
    @Body() notification: CreateNotificationRequest,
  ): Promise<ApiResponse> {
    try {
      this.logger.log('Creating a new notification', notification);

      const response = await sendKafkaRequest(
        this.notificationClient.send('notification.create', notification),
      );

      return new ApiResponse(
        'Notification created successfully',
        response,
        request.url,
      );
    } catch (error) {
      this.logger.error('Error creating notification', error.message);
      throw new RpcException(error);
    }
  }

  @Put('update/:idNotifications')
  @ApiOperation({
    summary: 'Method PUT - Update an existing notification ✅',
    description:
      'This endpoint allows you to update an existing notification by providing the notification ID and the updated details.',
  })
  async updateNotification(
    @Req() request: Request,
    @Param('idNotifications', ParseIntPipe) idNotifications: number,
    @Body() notification: UpdateNotificationRequest,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.notificationClient.send('notification.update', {
          idNotifications,
          notification,
        }),
      );

      return new ApiResponse(
        'Notification updated successfully',
        response,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Retrieve all notifications ✅',
    description:
      'This endpoint retrieves all notifications stored in the system.',
  })
  async findAllNotifications(@Req() request: Request): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.notificationClient.send('notification.find-all', {}),
      );

      return new ApiResponse(
        'Notifications retrieved successfully',
        response,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idNotifications')
  @ApiOperation({
    summary: 'Method GET - Retrieve a notification by ID ✅',
    description: 'This endpoint retrieves a specific notification by its ID.',
  })
  async findNotificationById(
    @Req() request: Request,
    @Param('idNotifications', ParseIntPipe) idNotifications: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.notificationClient.send('notification.find-by-id', {
          idNotifications,
        }),
      );

      return new ApiResponse(
        'Notification retrieved successfully',
        response,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-email/:email')
  @ApiOperation({
    summary: 'Method GET - Retrieve a notification by email ✅',
    description:
      'This endpoint retrieves a specific notification by the email associated with it.',
  })
  async findNotificationByEmail(
    @Req() request: Request,
    @Param('email') email: string,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.notificationClient.send('notification.find-by-email', { email }),
      );

      return new ApiResponse(
        'Notification retrieved successfully',
        response,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idNotifications')
  @ApiOperation({
    summary: 'Method DELETE - Delete a notification by ID ✅',
    description:
      'This endpoint deletes a specific notification by its ID. If the notification does not exist, it returns an error.',
  })
  async deleteNotification(
    @Req() request: Request,
    @Param('idNotifications', ParseIntPipe) idNotifications: number,
  ): Promise<ApiResponse> {
    try {
      const response = await sendKafkaRequest(
        this.notificationClient.send('notification.delete', {
          idNotifications,
        }),
      );

      return new ApiResponse(
        'Notification deleted successfully',
        response,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
