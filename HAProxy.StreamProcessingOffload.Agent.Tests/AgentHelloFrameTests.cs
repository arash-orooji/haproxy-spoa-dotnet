using HAProxy.StreamProcessingOffload.Agent.Frames;
using HAProxy.StreamProcessingOffload.Agent.Payloads;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace HAProxy.StreamProcessingOffload.Agent.Tests
{
    [TestFixture]
    public class AgentHelloFrameTests
    {
        private AgentHelloFrame frame;

        [SetUp]
        public void Setup()
        {
            this.frame = new AgentHelloFrame("1.2.3", 12345, new string[] { "capability1", "capability2" });
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
        public void Constructor_VersionIsExpectedValue()
        {
            // assert
            ClassicAssert.AreEqual("1.2.3", ((KeyValueListPayload)this.frame.Payload).KeyValueItems["version"].Value);
        }

        [Test]
        public void Constructor_MaxFrameSizeIsExpectedValue()
        {
            // assert
            ClassicAssert.AreEqual(12345, ((KeyValueListPayload)this.frame.Payload).KeyValueItems["max-frame-size"].Value);
        }

        [Test]
        public void Constructor_CapabilitiesIsExpectedValue()
        {
            // assert
            ClassicAssert.AreEqual("capability1,capability2", ((KeyValueListPayload)this.frame.Payload).KeyValueItems["capabilities"].Value);
        }
    }
}