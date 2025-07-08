import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
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
import { CreateUserTypeRequest } from '../../domain/schemas/dto/request/create.user-type.request';
import { UpdateUserTypeRequest } from '../../domain/schemas/dto/request/update.user-type.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('user-type')
@ApiTags('user-type')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class UserTypeGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.authenticationKafkaClient)
    private readonly userTypeClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.userTypeClient.subscribeToResponseOf('user-type.create');
    this.userTypeClient.subscribeToResponseOf('user-type.update');
    this.userTypeClient.subscribeToResponseOf('user-type.find-all');
    this.userTypeClient.subscribeToResponseOf('user-type.find-by-id');
    this.userTypeClient.subscribeToResponseOf('user-type.find-by-name');
    this.userTypeClient.subscribeToResponseOf('user-type.find-like-name');
    this.userTypeClient.subscribeToResponseOf('user-type.delete');
    await this.userTypeClient.connect();
    console.log(this.userTypeClient['responsePatterns']);
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Get all user types ✅',
    description: 'Retrieve all user types from the authentication service.',
  })
  async findAll(@Req() request: Request): Promise<ApiResponse> {
    try {
      console.log(`Sending request to user-type.find-all`);
      const userTypes = await sendKafkaRequest(
        this.userTypeClient.send('user-type.find-all', {}),
      );
      console.log(`Response received from user-type.find-all`);
      return new ApiResponse(
        'User types retrieved successfully',
        userTypes,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idUserType')
  @ApiOperation({
    summary: 'Method GET - Get user type by ID ✅',
    description:
      'Retrieve a user type by its ID from the authentication service.',
  })
  async findById(
    @Req() request: Request,
    @Param('idUserType', ParseIntPipe) idUserType: number,
  ): Promise<ApiResponse> {
    try {
      const userType = await sendKafkaRequest(
        this.userTypeClient.send('user-type.find-by-id', { idUserType }),
      );
      return new ApiResponse(
        'User type retrieved successfully',
        userType,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new user type ✅',
    description: 'Create a new user type in the authentication service.',
  })
  async create(
    @Req() request: Request,
    @Body() userTypeRequest: CreateUserTypeRequest,
  ): Promise<ApiResponse> {
    try {
      const createdUserType = await sendKafkaRequest(
        this.userTypeClient.send('user-type.create', userTypeRequest),
      );
      return new ApiResponse(
        'User type created successfully',
        createdUserType,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idUserType')
  @ApiOperation({
    summary: 'Method PUT - Update user type by ID ✅',
    description:
      'Update an existing user type by its ID in the authentication service.',
  })
  async update(
    @Req() request: Request,
    @Param('idUserType', ParseIntPipe) idUserType: number,
    @Body() userTypeRequest: UpdateUserTypeRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedUserType = await sendKafkaRequest(
        this.userTypeClient.send('user-type.update', {
          idUserType,
          userTypeRequest,
        }),
      );
      return new ApiResponse(
        'User type updated successfully',
        updatedUserType,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idUserType')
  @ApiOperation({
    summary: 'Method DELETE - Delete user type by ID ✅',
    description: 'Delete a user type by its ID in the authentication service.',
  })
  async delete(
    @Req() request: Request,
    @Param('idUserType', ParseIntPipe) idUserType: number,
  ): Promise<ApiResponse> {
    try {
      const isDeleted = await sendKafkaRequest(
        this.userTypeClient.send('user-type.delete', { idUserType }),
      );
      return new ApiResponse(
        'User type deleted successfully',
        isDeleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Find user type by name ✅',
    description: 'Find a user type by its name in the authentication service.',
  })
  async findByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const userType = await sendKafkaRequest(
        this.userTypeClient.send('user-type.find-by-name', { name }),
      );
      return new ApiResponse(
        'User type found successfully',
        userType,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get(`find-like-name/:name`)
  @ApiOperation({
    summary: 'Method GET - Find user types like name ✅',
    description:
      'Find user types that match a given name pattern in the authentication service.',
  })
  async findLikeName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const userTypes = await sendKafkaRequest(
        this.userTypeClient.send('user-type.find-like-name', { name }),
      );
      return new ApiResponse(
        'User types found successfully',
        userTypes,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
