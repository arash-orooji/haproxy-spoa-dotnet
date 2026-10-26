using HAProxy.StreamProcessingOffload.Agent.Frames;
using HAProxy.StreamProcessingOffload.Agent.Payloads;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace HAProxy.StreamProcessingOffload.Agent.Tests
{
    [TestFixture]
    public class AgentDisconnectFrameTests
    {
        private AgentDisconnectFrame frame;

        [SetUp]
        public void Setup()
        {
            this.frame = new AgentDisconnectFrame(Status.Normal, "Test");
        }

        [Test]
        public void Constructor_StreamIdIsZero()
        {
            // assert
            ClassicAssert.AreEqual(0, this.frame.Metadata.StreamId.Value);
        }

        [Test]
        public void Constructor_FrameIdIsZero()
        {
            // assert
            ClassicAssert.AreEqual(0, this.frame.Metadata.FrameId.Value);
        }

        [Test]
        public void Constructor_FinIsTrue()
        {
            // assert
            ClassicAssert.IsTrue(this.frame.Metadata.Flags.Fin);
        }

        [Test]
        public void Constructor_AbortIsFalse()
        {
            // assert
            ClassicAssert.IsFalse(this.frame.Metadata.Flags.Abort);
        }

        [Test]
        public void Constructor_StatusIsExpectedValue()
        {
            // assert
            ClassicAssert.AreEqual(0, ((KeyValueListPayload)this.frame.Payload).KeyValueItems["status-code"].Value);
        }

        [Test]
        public void Constructor_MessageIsExpectedValue()
        {
            // assert
            ClassicAssert.AreEqual("Test", ((KeyValueListPayload)this.frame.Payload).KeyValueItems["message"].Value);
        }
    }
}