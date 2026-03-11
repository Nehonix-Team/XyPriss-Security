/***************************************************************************
 * XyPriss Security Core - High Performance Security Library
 *
 * @author NEHONIX (https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL)
 *
 * Copyright (c) 2025 NEHONIX. All rights reserved.
 *
 * This License governs the use, modification, and distribution of software
 * provided by NEHONIX under its open source projects.
 * NEHONIX is committed to fostering collaborative innovation while strictly
 * protecting its intellectual property rights.
 ****************************************************************************/

package engine

import (
	"sync"
)

// Task represents a unit of work to be executed by the engine
type Task struct {
	ID      string
	Payload func() interface{}
	Result  interface{}
}

// Engine manages a pool of workers (goroutines)
type Engine struct {
	workerCount int
	taskQueue   chan *Task
	wg          sync.WaitGroup
}

// NewEngine creates a new execution engine
func NewEngine(workerCount int) *Engine {
	return &Engine{
		workerCount: workerCount,
		taskQueue:   make(chan *Task, 100),
	}
}

// Start initializes the worker pool
func (e *Engine) Start() {
	for i := 0; i < e.workerCount; i++ {
		go func() {
			for task := range e.taskQueue {
				task.Result = task.Payload()
				e.wg.Done()
			}
		}()
	}
}

// Dispatch sends a task to the worker pool
func (e *Engine) Dispatch(task *Task) {
	e.wg.Add(1)
	e.taskQueue <- task
}

// Wait blocks until all tasks are completed
func (e *Engine) Wait() {
	e.wg.Wait()
}
