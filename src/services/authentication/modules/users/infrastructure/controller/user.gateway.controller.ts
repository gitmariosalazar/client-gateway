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
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { CreateUserRequest } from '../../domain/schemas/dto/request/create.user.request';
import { UpdateUserRequest } from '../../domain/schemas/dto/request/update.user.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('user')
@ApiTags('user')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class UserGatewayController implements OnModuleInit {
  private readonly logger = new Logger(UserGatewayController.name);
  constructor(
    @Inject(environments.authenticationKafkaClient)
    private readonly userClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.userClient.subscribeToResponseOf('user.create');
    this.userClient.subscribeToResponseOf('user.update');
    this.userClient.subscribeToResponseOf('user.find-all');
    this.userClient.subscribeToResponseOf('user.find-by-id');
    this.userClient.subscribeToResponseOf('user.find-by-email');
    this.userClient.subscribeToResponseOf('user.delete');
    await this.userClient.connect();
    console.log(this.userClient['responsePatterns']);
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all users ✅',
    description: 'Retrieves a list of all users in the system.',
  })
  async findAll(@Req() request: Request): Promise<ApiResponse> {
    try {
      this.logger.warn(
        `[UserGatewayController] Sending request to find all users`,
      );
      const users = await sendKafkaRequest(
        this.userClient.send('user.find-all', {}),
      );
      this.logger.warn(
        `[UserGatewayController] Received response for all users`,
      );
      return new ApiResponse(
        'Users retrieved successfully',
        users,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idUser')
  @ApiOperation({
    summary: 'Method GET - Find user by ID ✅',
    description: 'Retrieves a user by its ID.',
  })
  async findById(
    @Req() request: Request,
    @Param('idUser', ParseIntPipe) idUser: number,
  ): Promise<ApiResponse> {
    try {
      const user = await sendKafkaRequest(
        this.userClient.send('user.find-by-id', { idUser }),
      );
      return new ApiResponse('User retrieved successfully', user, request.url);
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-email/:userEmail')
  @ApiOperation({
    summary: 'Method GET - Find user by email ✅',
    description: 'Retrieves a user by its email.',
  })
  async findByEmail(
    @Req() request: Request,
    @Param('userEmail') userEmail: string,
  ): Promise<ApiResponse> {
    try {
      const user = await sendKafkaRequest(
        this.userClient.send('user.find-by-email', { userEmail: userEmail }),
      );
      return new ApiResponse('User retrieved successfully', user, request.url);
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new user ✅',
    description: 'Creates a new user in the system.',
  })
  async create(
    @Req() request: Request,
    @Body() userRequest: CreateUserRequest,
  ): Promise<ApiResponse> {
    try {
      const createdUser = await sendKafkaRequest(
        this.userClient.send('user.create', userRequest),
      );
      return new ApiResponse(
        'User created successfully',
        createdUser,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idUser')
  @ApiOperation({
    summary: 'Method POST - Update user by ID ✅',
    description: 'Updates an existing user by its ID.',
  })
  async update(
    @Req() request: Request,
    @Param('idUser', ParseIntPipe) idUser: number,
    @Body() userRequest: UpdateUserRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedUser = await sendKafkaRequest(
        this.userClient.send('user.update', { idUser, userRequest }),
      );
      return new ApiResponse(
        'User updated successfully',
        updatedUser,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idUser')
  @ApiOperation({
    summary: 'Method DELETE - Delete user by ID ✅',
    description: 'Deletes a user by its ID.',
  })
  async delete(
    @Req() request: Request,
    @Param('idUser', ParseIntPipe) idUser: number,
  ): Promise<ApiResponse> {
    try {
      const deleted = await sendKafkaRequest(
        this.userClient.send('user.delete', { idUser }),
      );
      return new ApiResponse('User deleted successfully', deleted, request.url);
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
