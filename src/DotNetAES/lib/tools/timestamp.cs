using System;

namespace DotNetAES
{
    public partial class Helpers
    {
        //#########################################
        //#######    Timestamp Functions    #######
        //#########################################

        /// <summary>
        /// Converts a double into a byte arrau
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public byte[] ConvertDoubleToByteArray(double value)
        {
            return BitConverter.GetBytes(value);
        }

        /// <summary>
        /// Converts a byte array into a double
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public double ConvertByteArrayToDouble(byte[] value)
        {
            return BitConverter.ToDouble(value, 0);
        }

        /// <summary>
        /// Converts a unix timestamp back into DateTime object
        /// </summary>
        /// <param name="unixTimeStamp"></param>
        /// <returns></returns>
        public DateTime UnixTimeStampToDateTime(double unixTimeStamp)
		{
            DateTime dtDateTime = new DateTime(1970,1,1,0,0,0,0,DateTimeKind.Utc);
			dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
			return dtDateTime;
		}

        /// <summary>
        /// Converts a DateTime object into a unix timestamp string
        /// </summary>
        /// <param name="dateTime"></param>
        /// <returns></returns>
		public double DateTimeToUnixTimestamp(DateTime dateTime)
		{
			return (TimeZoneInfo.ConvertTimeToUtc(dateTime) - 
				   new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
		}
    }
}