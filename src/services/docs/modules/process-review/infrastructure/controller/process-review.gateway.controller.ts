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
import { CreateProcessReviewRequest } from '../../domain/schemas/dto/request/create.process-review.request';
import { UpdateProcessReviewRequest } from '../../domain/schemas/dto/request/update.process-review.request';
import { AuthGuard } from 'src/auth/guard/auth.guard';
import { sendKafkaRequest } from 'src/shared/utils/kafka/send.kafka.request';

@Controller('process-review')
@ApiTags('Process Review')
@ApiBearerAuth()
@UseGuards(AuthGuard)
export class ProcessReviewGatewayController implements OnModuleInit {
  constructor(
    @Inject(environments.documentsKafkaClient)
    private readonly processReviewClient: ClientKafka,
  ) {}

  async onModuleInit() {
    this.processReviewClient.subscribeToResponseOf('process-review.create');
    this.processReviewClient.subscribeToResponseOf('process-review.update');
    this.processReviewClient.subscribeToResponseOf('process-review.find-by-id');
    this.processReviewClient.subscribeToResponseOf('process-review.find-all');
    this.processReviewClient.subscribeToResponseOf(
      'process-review.find-by-process-id',
    );
    this.processReviewClient.subscribeToResponseOf('process-review.delete');
    await this.processReviewClient.connect();
  }

  @Post('create')
  @ApiOperation({
    summary: 'Method POST - Create a new process review ✅',
    description: 'Creates a new process review.',
  })
  async createProcessReview(
    @Req() request: Request,
    @Body() processReview: CreateProcessReviewRequest,
  ): Promise<ApiResponse> {
    try {
      console.log(processReview);
      const processReviewResponse = await sendKafkaRequest(
        this.processReviewClient.send('process-review.create', processReview),
      );
      return new ApiResponse(
        'Process review created successfully',
        processReviewResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Put('update/:idProcessReview')
  @ApiOperation({
    summary: 'Method PUT - Update a process review ✅',
    description: 'Updates an existing process review by its ID.',
  })
  async updateProcessReview(
    @Req() request: Request,
    @Param('idProcessReview', ParseIntPipe) idProcessReview: number,
    @Body() processReview: UpdateProcessReviewRequest,
  ): Promise<ApiResponse> {
    try {
      const processReviewResponse = await sendKafkaRequest(
        this.processReviewClient.send('process-review.update', {
          idProcessReview,
          processReview,
        }),
      );
      return new ApiResponse(
        'Process review updated successfully',
        processReviewResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-id/:idProcessReview')
  @ApiOperation({
    summary: 'Method GET - Find process review by ID ✅',
    description: 'Retrieves a process review by its ID.',
  })
  async findProcessReviewById(
    @Req() request: Request,
    @Param('idProcessReview', ParseIntPipe) idProcessReview: number,
  ): Promise<ApiResponse> {
    try {
      const processReviewResponse = await sendKafkaRequest(
        this.processReviewClient.send('process-review.find-by-id', {
          idProcessReview,
        }),
      );
      return new ApiResponse(
        'Process review retrieved successfully',
        processReviewResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-all')
  @ApiOperation({
    summary: 'Method GET - Find all process reviews ✅',
    description: 'Retrieves all process reviews.',
  })
  async findAllProcessReviews(@Req() request: Request): Promise<ApiResponse> {
    try {
      const processReviewResponse = await sendKafkaRequest(
        this.processReviewClient.send('process-review.find-all', {}),
      );
      return new ApiResponse(
        'Process reviews retrieved successfully',
        processReviewResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Get('find-by-process-id/:idProcess')
  @ApiOperation({
    summary: 'Method GET - Find process reviews by process ID ✅',
    description: 'Retrieves process reviews by their associated process ID.',
  })
  async findProcessReviewsByProcessId(
    @Req() request: Request,
    @Param('idProcess', ParseIntPipe) idProcess: number,
  ): Promise<ApiResponse> {
    try {
      const processReviewResponse = await sendKafkaRequest(
        this.processReviewClient.send('process-review.find-by-process-id', {
          idProcess,
        }),
      );
      return new ApiResponse(
        'Process reviews by process ID retrieved successfully',
        processReviewResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }

  @Delete('delete/:idProcessReview')
  @ApiOperation({
    summary: 'Method DELETE - Delete a process review ✅',
    description: 'Deletes a process review by its ID.',
  })
  async deleteProcessReview(
    @Req() request: Request,
    @Param('idProcessReview', ParseIntPipe) idProcessReview: number,
  ): Promise<ApiResponse> {
    try {
      const deleteResponse = await sendKafkaRequest(
        this.processReviewClient.send('process-review.delete', {
          idProcessReview,
        }),
      );
      return new ApiResponse(
        'Process review deleted successfully',
        deleteResponse,
        request.url,
      );
    } catch (error) {
      throw new RpcException(error);
    }
  }
}
