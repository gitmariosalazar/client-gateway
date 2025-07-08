import {
  Body,
  Param,
  ParseIntPipe,
  Controller,
  Inject,
  Post,
  Req,
  Put,
  Get,
  Delete,
  OnModuleInit,
  UseGuards,
} from '@nestjs/common';
import { ClientKafka, RpcException } from '@nestjs/microservices';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { environments } from 'src/settings/environments/environments';
import { CreateProcessDocumentRequest } from '../../domain/schemas/dto/request/create.process-document.request';
import { ApiResponse } from 'src/shared/errors/responses/ApiResponse';
import { UpdateProcessDocumentRequest } from '../../domain/schemas/dto/request/update.process-document.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('process-documents')
@ApiTags('Process Documents')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class ProcessDocumentGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly processDocumentSClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.processDocumentSClient.subscribeToResponseOf(
      'processDocuments.create',
    );
    this.processDocumentSClient.subscribeToResponseOf(
      'processDocuments.update',
    );
    this.processDocumentSClient.subscribeToResponseOf(
      'processDocuments.find-all',
    );
    this.processDocumentSClient.subscribeToResponseOf(
      'processDocuments.find-by-id',
    );
    this.processDocumentSClient.subscribeToResponseOf(
      'processDocuments.find-by-process',
    );
    this.processDocumentSClient.subscribeToResponseOf(
      'processDocuments.find-by-document',
    );
    this.processDocumentSClient.subscribeToResponseOf(
      'processDocuments.delete',
    );
    await this.processDocumentSClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new process document ✅',
    description: 'Creates a new process document with the provided details.',
  })
  async createProcessDocument(
    @Req() request: Request,
    @Body() processDocument: CreateProcessDocumentRequest,
  ): Promise<ApiResponse> {
    try {
      const processDocumentResponse = await sendKafkaRequest(
        this.processDocumentSClient.send(
          'processDocuments.create',
          processDocument,
        ),
      );
      return new ApiResponse(
        'Process document created successfully',
        processDocumentResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idProcessDocument')
  @ApiOperation({
    summary: 'Method PUT - Update a process document ✅',
    description:
      'Updates an existing process document with the provided details.',
  })
  async updateProcessDocument(
    @Req() request: Request,
    @Param('idProcessDocument', ParseIntPipe) idProcessDocument: number,
    @Body() processDocument: UpdateProcessDocumentRequest,
  ): Promise<ApiResponse> {
    try {
      const processDocumentResponse = await sendKafkaRequest(
        this.processDocumentSClient.send('processDocuments.update', {
          idProcessDocument,
          processDocument,
        }),
      );
      return new ApiResponse(
        'Process document updated successfully',
        processDocumentResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all process documents ✅',
    description: 'Retrieves a list of all process documents.',
  })
  async findAllProcessDocuments(@Req() request: Request): Promise<ApiResponse> {
    try {
      const processDocumentsResponse = await sendKafkaRequest(
        this.processDocumentSClient.send('processDocuments.find-all', {}),
      );
      return new ApiResponse(
        'Process documents retrieved successfully',
        processDocumentsResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idProcessDocument')
  @ApiOperation({
    summary: 'Method GET - Find process document by ID ✅',
    description: 'Retrieves a process document by its ID.',
  })
  async findProcessDocumentById(
    @Req() request: Request,
    @Param('idProcessDocument', ParseIntPipe) idProcessDocument: number,
  ): Promise<ApiResponse> {
    try {
      const processDocumentResponse = await sendKafkaRequest(
        this.processDocumentSClient.send('processDocuments.find-by-id', {
          idProcessDocument,
        }),
      );
      return new ApiResponse(
        'Process document retrieved successfully',
        processDocumentResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-process/:idProcess')
  @ApiOperation({
    summary: 'Method GET - Find process documents by process ID ✅',
    description:
      'Retrieves process documents associated with a specific process ID.',
  })
  async findProcessDocumentsByProcessId(
    @Req() request: Request,
    @Param('idProcess', ParseIntPipe) idProcess: number,
  ): Promise<ApiResponse> {
    try {
      const processDocumentsResponse = await sendKafkaRequest(
        this.processDocumentSClient.send('processDocuments.find-by-process', {
          idProcess,
        }),
      );
      return new ApiResponse(
        'Process documents by process ID retrieved successfully',
        processDocumentsResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-document/:idDocument')
  @ApiOperation({
    summary: 'Method GET - Find process documents by document ID ✅',
    description:
      'Retrieves process documents associated with a specific document ID.',
  })
  async findProcessDocumentsByDocumentId(
    @Req() request: Request,
    @Param('idDocument', ParseIntPipe) idDocument: number,
  ): Promise<ApiResponse> {
    try {
      const processDocumentsResponse = await sendKafkaRequest(
        this.processDocumentSClient.send('processDocuments.find-by-document', {
          idDocument,
        }),
      );
      return new ApiResponse(
        'Process documents by document ID retrieved successfully',
        processDocumentsResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idProcessDocument')
  @ApiOperation({
    summary: 'Method DELETE - Delete a process document ✅',
    description: 'Deletes a process document by its ID.',
  })
  async deleteProcessDocument(
    @Req() request: Request,
    @Param('idProcessDocument', ParseIntPipe) idProcessDocument: number,
  ): Promise<ApiResponse> {
    try {
      const isDeleted = await sendKafkaRequest(
        this.processDocumentSClient.send('processDocuments.delete', {
          idProcessDocument,
        }),
      );
      return new ApiResponse(
        'Process document deleted successfully',
        isDeleted,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
