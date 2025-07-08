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
import { CreatePermissionRequest } from '../../domain/schemas/dto/request/create.permission.request';
import { UpdatePermissionRequest } from '../../domain/schemas/dto/request/update.permission.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('permission')
@ApiTags('permission')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class PermissionGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.authenticationKafkaClient)
    private readonly permissionClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.permissionClient.subscribeToResponseOf('permission.create');
    this.permissionClient.subscribeToResponseOf('permission.update');
    this.permissionClient.subscribeToResponseOf('permission.find-all');
    this.permissionClient.subscribeToResponseOf('permission.find-by-id');
    this.permissionClient.subscribeToResponseOf('permission.find-by-name');
    this.permissionClient.subscribeToResponseOf('permission.delete');
    await this.permissionClient.connect();
    console.log(this.permissionClient['responsePatterns']);
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all permissions ✅',
    description: 'Retrieves a list of all permissions in the system.',
  })
  async findAll(@Req() request: Request): Promise<ApiResponse> {
    try {
      const permissions = await sendKafkaRequest(
        this.permissionClient.send('permission.find-all', {}),
      );
      return new ApiResponse(
        'Permissions retrieved successfully',
        permissions,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idPermission')
  @ApiOperation({
    summary: 'Method GET - Find permission by ID ✅',
    description: 'Retrieves a permission by its ID.',
  })
  async findById(
    @Req() request: Request,
    @Param('idPermission', ParseIntPipe) idPermission: number,
  ): Promise<ApiResponse> {
    try {
      const permission = await sendKafkaRequest(
        this.permissionClient.send('permission.find-by-id', { idPermission }),
      );
      return new ApiResponse(
        'Permission retrieved successfully',
        permission,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Find permission by name ✅',
    description: 'Retrieves a permission by its name.',
  })
  async findByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const permission = await sendKafkaRequest(
        this.permissionClient.send('permission.find-by-name', { name }),
      );
      return new ApiResponse(
        'Permission retrieved successfully',
        permission,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new permission ✅',
    description: 'Creates a new permission in the system.',
  })
  async create(
    @Req() request: Request,
    @Body() permissionRequest: CreatePermissionRequest,
  ): Promise<ApiResponse> {
    try {
      const createdPermission = await sendKafkaRequest(
        this.permissionClient.send('permission.create', permissionRequest),
      );
      return new ApiResponse(
        'Permission created successfully',
        createdPermission,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idPermission')
  @ApiOperation({
    summary: 'Method PUT - Update permission by ID ✅',
    description: 'Updates an existing permission by its ID.',
  })
  async update(
    @Req() request: Request,
    @Param('idPermission', ParseIntPipe) idPermission: number,
    @Body() permissionRequest: UpdatePermissionRequest,
  ): Promise<ApiResponse> {
    try {
      const updatedPermission = await sendKafkaRequest(
        this.permissionClient.send('permission.update', {
          idPermission,
          permissionRequest,
        }),
      );
      return new ApiResponse(
        'Permission updated successfully',
        updatedPermission,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idPermission')
  @ApiOperation({
    summary: 'Method DELETE - Delete permission by ID ✅',
    description: 'Deletes a permission by its ID.',
  })
  async delete(
    @Req() request: Request,
    @Param('idPermission', ParseIntPipe) idPermission: number,
  ): Promise<ApiResponse> {
    try {
      const isDeleted = await sendKafkaRequest(
        this.permissionClient.send('permission.delete', { idPermission }),
      );
      return new ApiResponse(
        'Permission deleted successfully',
        isDeleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
