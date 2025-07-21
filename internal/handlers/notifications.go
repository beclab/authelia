package handlers

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/nats-io/nats.go"
	"k8s.io/klog/v2"
)

type Topic string

const (
	TopicLogin         Topic = "Login"
	TopicLogout        Topic = "Logout"
	TopicOnFirstFactor Topic = "OnFirstFactor"
	TopicLoginFailed   Topic = "LoginFailed"
	TopicSignCancel    Topic = "SignCancel"
)

func (t Topic) String() string {
	return string(t)
}

func (t Topic) send(ctx *middlewares.AutheliaCtx, username string, additional ...map[string]interface{}) {
	sendWithTopic(ctx, username, t, additional...)
}

func sendNotification(user string, data interface{}) error {
	natsHost := os.Getenv("NATS_HOST")
	natsPort := os.Getenv("NATS_PORT")
	natsUsername := os.Getenv("NATS_USERNAME")
	natsPassword := os.Getenv("NATS_PASSWORD")
	natsSubject := os.Getenv("NATS_SUBJECT_FOR_USERS")

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%s", natsHost, natsPort), nats.UserInfo(natsUsername, natsPassword))
	if err != nil {
		return fmt.Errorf("error connecting to NATS: %v", err)
	}
	klog.Infoln("Connected to NATS", natsHost, natsPort, natsUsername)

	msg, err := json.Marshal(data)
	if err != nil {
		klog.Error("encode msg error, ", err)
		return err
	}
	klog.Infof("message... %s", string(msg))

	err = nc.Publish(natsSubject, msg)
	if err != nil {
		klog.Error("publish message to nats error, ", err)
		return err
	}

	klog.Infof("published to subject: %s success ", natsSubject)
	return nil
}

func sendWithTopic(ctx *middlewares.AutheliaCtx, username string, topic Topic, additionals ...map[string]interface{}) {
	payload := &struct {
		User string `json:"user"`
		IP   string `json:"ip"`
	}{
		User: username,
		IP:   ctx.RemoteIP().String(),
	}

	data := map[string]interface{}{
		"payload": payload,
		"topic":   topic,
	}

	for _, additional := range additionals {
		for k, v := range additional {
			data[k] = v
		}
	}

	if err := sendNotification(username, data); err != nil {
		ctx.Logger.Errorf("send notification to user %s error, %+v", username, err)
	}
}
