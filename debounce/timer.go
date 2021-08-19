package debounce

import (
	"errors"
	"strings"
	"time"
)

var (
	err_OutOfRange    = errors.New("Duration out of range")
	err_MinLTMax      = errors.New("Min duration must be less than max duration")
	err_InvalidFormat = errors.New("Invalid duration format")
)

func New(min, max time.Duration) (*Timer, error) {
	if min < time.Duration(0) || max < time.Duration(0) {
		return nil, err_OutOfRange
	}

	if min > max {
		return nil, err_MinLTMax
	}

	t := &Timer{
		result:  make(chan struct{}, 8),
		trigger: make(chan struct{}),
		min:     min,
		max:     max,
	}

	go t.run()
	return t, nil
}

func NewFromString(s string) (*Timer, error) {
	parts := strings.Split(s, ":")
	if len(parts) == 1 {
		period, err := time.ParseDuration(s)
		if err != nil {
			return nil, err
		}

		return New(period, period)
	} else if len(parts) == 2 {
		min, err := time.ParseDuration(parts[0])
		if err != nil {
			return nil, err
		}

		max, err := time.ParseDuration(parts[1])
		if err != nil {
			return nil, err
		}

		return New(min, max)
	} else {
		return nil, err_InvalidFormat
	}
}

type Timer struct {
	result  chan struct{}
	trigger chan struct{}
	min     time.Duration
	max     time.Duration
}

func (t *Timer) Chan() <-chan struct{} {
	return t.result
}

func (t *Timer) Trigger() {
	t.trigger <- struct{}{}
}

func (t *Timer) run() {
	mn := time.NewTimer(5 * time.Minute)
	mx := time.NewTimer(5 * time.Minute)
	mn.Stop()
	mx.Stop()

	for {
		<-t.trigger
		mn.Reset(t.min)
		mx.Reset(t.max)

	duty:
		for {
			select {
			case <-t.trigger:
				if !mn.Stop() {
					<-mn.C
				}
				mn.Reset(t.min)

			case <-mn.C:
				if !mx.Stop() {
					<-mx.C
				}
				
				break duty
				
			case <-mx.C:
				if !mn.Stop() {
					<-mn.C
				}
				
				break duty
			}
		}
		
		t.result <- struct{}{}
	}
}
