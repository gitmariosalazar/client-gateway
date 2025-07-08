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
import { CreatePriorityRequest } from '../../domain/schemas/dto/request/create.priority.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdatePriorityRequest } from '../../domain/schemas/dto/request/update.priority.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('priority')
@ApiTags('Priority')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class PriorityGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.notificationKafkaClient)
    private readonly priorityClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.priorityClient.subscribeToResponseOf('priority.create');
    this.priorityClient.subscribeToResponseOf('priority.update');
    this.priorityClient.subscribeToResponseOf('priority.find-all');
    this.priorityClient.subscribeToResponseOf('priority.find-by-id');
    this.priorityClient.subscribeToResponseOf('priority.find-by-name');
    this.priorityClient.subscribeToResponseOf('priority.delete');
    await this.priorityClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new priority ✅',
    description: 'Creates a new priority in the system.',
  })
  async createPriority(
    @Req() request: Request,
    @Body() priority: CreatePriorityRequest,
  ): Promise<ApiResponse> {
    try {
      const priorityResponse = await sendKafkaRequest(
        this.priorityClient.send('priority.create', { priority }),
      );
      return new ApiResponse(
        'Priority created successfully.',
        priorityResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idPriority')
  @ApiOperation({
    summary: 'Method PUT - Update an existing priority ✅',
    description: 'Updates an existing priority in the system.',
  })
  async updatePriority(
    @Req() request: Request,
    @Param('idPriority', ParseIntPipe) idPriority: number,
    @Body() priority: UpdatePriorityRequest,
  ): Promise<ApiResponse> {
    try {
      const priorityResponse = await sendKafkaRequest(
        this.priorityClient.send('priority.update', { idPriority, priority }),
      );
      return new ApiResponse(
        'Priority updated successfully.',
        priorityResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Retrieve all priorities ✅',
    description: 'Fetches all priorities from the system.',
  })
  async findAllPriorities(@Req() request: Request): Promise<ApiResponse> {
    try {
      const priorities = await sendKafkaRequest(
        this.priorityClient.send('priority.find-all', {}),
      );
      return new ApiResponse(
        'Priorities retrieved successfully.',
        priorities,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idPriority')
  @ApiOperation({
    summary: 'Method DELETE - Delete a priority by ID ✅',
    description: 'Deletes a priority by its ID from the system.',
  })
  async deletePriority(
    @Req() request: Request,
    @Param('idPriority', ParseIntPipe) idPriority: number,
  ): Promise<ApiResponse> {
    try {
      const deleted = await sendKafkaRequest(
        this.priorityClient.send('priority.delete', { idPriority }),
      );
      return new ApiResponse(
        'Priority deleted successfully.',
        deleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idPriority')
  @ApiOperation({
    summary: 'Method GET - Retrieve a priority by ID ✅',
    description: 'Fetches a priority by its ID from the system.',
  })
  async findPriorityById(
    @Req() request: Request,
    @Param('idPriority', ParseIntPipe) idPriority: number,
  ): Promise<ApiResponse> {
    try {
      const priority = await sendKafkaRequest(
        this.priorityClient.send('priority.find-by-id', { idPriority }),
      );
      return new ApiResponse(
        'Priority retrieved successfully.',
        priority,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-name/:name')
  @ApiOperation({
    summary: 'Method GET - Retrieve a priority by name ✅',
    description: 'Fetches a priority by its name from the system.',
  })
  async findPriorityByName(
    @Req() request: Request,
    @Param('name') name: string,
  ): Promise<ApiResponse> {
    try {
      const priority = await sendKafkaRequest(
        this.priorityClient.send('priority.find-by-name', { name }),
      );
      return new ApiResponse(
        'Priority retrieved successfully.',
        priority,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
