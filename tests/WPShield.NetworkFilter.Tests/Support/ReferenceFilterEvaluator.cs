using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace WPShield.NetworkFilter.Tests.Support;

/// <summary>
/// An independent evaluator for the WinDivert filter subset WPShield generates: <c>and</c>, <c>or</c>,
/// <c>!</c>, parentheses, the fields <c>inbound</c>, <c>loopback</c>, <c>tcp.Syn</c>, <c>tcp.Ack</c>,
/// <c>ip.SrcAddr</c> and <c>ipv6.SrcAddr</c>, and the comparisons <c>==</c>, <c>&gt;=</c>, <c>&lt;=</c>.
/// Packets are evaluated as inbound and not loopback, as the self-test describes them. Anything else
/// fails to parse, which is how a test notices the builder writing something new.
/// </summary>
internal static class ReferenceFilterEvaluator
{
    public static bool TryParse(string filter, out Func<PacketHeaders, bool>? predicate)
    {
        try
        {
            var parser = new Parser(Tokenize(filter));
            predicate = parser.ParseExpression();
            if (!parser.AtEnd)
            {
                predicate = null;
                return false;
            }

            return true;
        }
        catch (FormatException)
        {
            predicate = null;
            return false;
        }
    }

    public static bool Evaluate(string filter, PacketHeaders headers)
    {
        Assert.True(TryParse(filter, out var predicate), $"unparseable filter: {filter}");
        return predicate!(headers);
    }

    private static List<string> Tokenize(string filter)
    {
        var tokens = new List<string>();
        var word = new System.Text.StringBuilder();
        void Flush()
        {
            if (word.Length > 0)
            {
                tokens.Add(word.ToString());
                word.Clear();
            }
        }

        foreach (var c in filter)
        {
            if (char.IsWhiteSpace(c))
            {
                Flush();
            }
            else if (c is '(' or ')' or '!')
            {
                Flush();
                tokens.Add(c.ToString());
            }
            else
            {
                word.Append(c);
            }
        }

        Flush();
        return tokens;
    }

    private sealed class Parser(List<string> tokens)
    {
        private int _position;

        public bool AtEnd => _position == tokens.Count;

        public Func<PacketHeaders, bool> ParseExpression()
        {
            var left = ParseAnd();
            while (Peek() == "or")
            {
                _position++;
                var right = ParseAnd();
                var l = left;
                left = h => l(h) || right(h);
            }

            return left;
        }

        private Func<PacketHeaders, bool> ParseAnd()
        {
            var left = ParseUnary();
            while (Peek() == "and")
            {
                _position++;
                var right = ParseUnary();
                var l = left;
                left = h => l(h) && right(h);
            }

            return left;
        }

        private Func<PacketHeaders, bool> ParseUnary()
        {
            var token = Next();
            if (token == "!")
            {
                var inner = ParseUnary();
                return h => !inner(h);
            }

            if (token == "(")
            {
                var inner = ParseExpression();
                Expect(")");
                return inner;
            }

            return token switch
            {
                "inbound" => _ => true,
                "loopback" => _ => false,
                "tcp.Syn" => h => h.Syn,
                "tcp.Ack" => h => h.Ack,
                "ip.SrcAddr" => Comparison(AddressFamily.InterNetwork),
                "ipv6.SrcAddr" => Comparison(AddressFamily.InterNetworkV6),
                _ => throw new FormatException($"unknown field '{token}'"),
            };
        }

        private Func<PacketHeaders, bool> Comparison(AddressFamily family)
        {
            var op = Next();
            var value = IPAddress.Parse(Next());
            if (value.AddressFamily != family)
            {
                throw new FormatException("address family does not match the field");
            }

            var operand = Number(value);
            return op switch
            {
                "==" => h => h.Source.AddressFamily == family && Number(h.Source) == operand,
                ">=" => h => h.Source.AddressFamily == family && Number(h.Source) >= operand,
                "<=" => h => h.Source.AddressFamily == family && Number(h.Source) <= operand,
                _ => throw new FormatException($"unknown operator '{op}'"),
            };
        }

        private static UInt128 Number(IPAddress address)
        {
            UInt128 value = 0;
            foreach (var b in address.GetAddressBytes())
            {
                value = (value << 8) | b;
            }

            return value;
        }

        private string? Peek() => _position < tokens.Count ? tokens[_position] : null;

        private string Next() => _position < tokens.Count ? tokens[_position++] : throw new FormatException("unexpected end");

        private void Expect(string token)
        {
            if (Next() != token)
            {
                throw new FormatException($"expected '{token}'");
            }
        }
    }
}
