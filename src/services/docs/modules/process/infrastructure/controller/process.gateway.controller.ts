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
import { CreateProcessRequest } from '../../domain/schemas/dto/request/create.process.request';
import { UpdateProcessRequest } from '../../domain/schemas/dto/request/update.process.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('process')
@ApiTags('Process')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class ProcessGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly processClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.processClient.subscribeToResponseOf('process.create');
    this.processClient.subscribeToResponseOf('process.update');
    this.processClient.subscribeToResponseOf('process.find-by-id');
    this.processClient.subscribeToResponseOf('process.find-by-process-number');
    this.processClient.subscribeToResponseOf('process.find-all');
    this.processClient.subscribeToResponseOf('process.delete');
    await this.processClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new process ✅',
    description: 'Creates a new process.',
  })
  async createProcess(
    @Req() request: Request,
    @Body() process: CreateProcessRequest,
  ): Promise<ApiResponse> {
    try {
      const processResponse = await sendKafkaRequest(
        this.processClient.send('process.create', process),
      );
      return new ApiResponse(
        'Process created successfully',
        processResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idProcess')
  @ApiOperation({
    summary: 'Method PUT - Update a process ✅',
    description: 'Updates an existing process by its ID.',
  })
  async updateProcess(
    @Req() request: Request,
    @Param('idProcess', ParseIntPipe) idProcess: number,
    @Body() process: UpdateProcessRequest,
  ): Promise<ApiResponse> {
    try {
      const processResponse = await sendKafkaRequest(
        this.processClient.send('process.update', { idProcess, process }),
      );
      return new ApiResponse(
        'Process updated successfully',
        processResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idProcess')
  @ApiOperation({
    summary: 'Method GET - Find process by ID ✅',
    description: 'Retrieves a process by its ID.',
  })
  async findProcessById(
    @Req() request: Request,
    @Param('idProcess', ParseIntPipe) idProcess: number,
  ): Promise<ApiResponse> {
    try {
      const processResponse = await sendKafkaRequest(
        this.processClient.send('process.find-by-id', { idProcess }),
      );
      return new ApiResponse(
        'Process found successfully',
        processResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-process-number/:processNumber')
  @ApiOperation({
    summary: 'Method GET - Find process by process number ✅',
    description: 'Retrieves a process by its process number.',
  })
  async findProcessByProcessNumber(
    @Req() request: Request,
    @Param('processNumber') processNumber: string,
  ): Promise<ApiResponse> {
    try {
      const processResponse = await sendKafkaRequest(
        this.processClient.send('process.find-by-process-number', {
          processNumber,
        }),
      );
      return new ApiResponse(
        'Process found successfully',
        processResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all processes ✅',
    description: 'Retrieves a list of all processes.',
  })
  async findAllProcesses(@Req() request: Request): Promise<ApiResponse> {
    try {
      const processesResponse = await sendKafkaRequest(
        this.processClient.send('process.find-all', {}),
      );
      return new ApiResponse(
        'Processes found successfully',
        processesResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idProcess')
  @ApiOperation({
    summary: 'Method DELETE - Delete a process ✅',
    description: 'Deletes a process by its ID.',
  })
  async deleteProcess(
    @Req() request: Request,
    @Param('idProcess', ParseIntPipe) idProcess: number,
  ): Promise<ApiResponse> {
    try {
      const result = await sendKafkaRequest(
        this.processClient.send('process.delete', { idProcess }),
      );
      return new ApiResponse(
        'Process deleted successfully',
        result,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
