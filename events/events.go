// cartio - An e-commerce API.
// Copyright (C) 2017 Eric Bittleman

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package events

import "context"

// Event holds data on system and domain events
type Event struct {
	Name     string
	EntityID string
	Payload  interface{}
}

// Observer implementers will be notified when events occur
type Observer interface {
	On(context.Context, Event)
}

// ObserverFunc function wrapper for Observer interface
type ObserverFunc func(context.Context, Event)

// On statifies Observer interface
func (o ObserverFunc) On(ctx context.Context, e Event) {
	o(ctx, e)
}

// Subject defines components that can be observered
type Subject interface {
	Subscribe(o Observer)
	Unsubscribe(o Observer)
	Emit(e Event)
	Notify(context.Context)
}

// Evented embeddedable interface that implements observer
type Evented struct {
	Events    []Event
	Observers []Observer
}

// Subscribe adds Observers to send events to
func (s *Evented) Subscribe(o Observer) {
	for _, cursor := range s.Observers {
		if cursor == o {
			return
		}
	}

	s.Observers = append(s.Observers, o)
}

// Unsubscribe removes an observer from being notified
func (s *Evented) Unsubscribe(o Observer) {
	for i, cursor := range s.Observers {
		if cursor == o {
			s.Observers[i] = s.Observers[len(s.Observers)-1]
			s.Observers[len(s.Observers)-1] = nil
			s.Observers = s.Observers[:len(s.Observers)-1]
			return
		}
	}
}

// Emit queues an event for notification.
func (s *Evented) Emit(e Event) {
	s.Events = append(s.Events, e)
}

// Notify flushes and sends notifications.
func (s *Evented) Notify(ctx context.Context) {
	for _, e := range s.Events {
		for _, o := range s.Observers {
			o.On(ctx, e)
		}
	}

	s.Events = nil
}
